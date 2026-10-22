/*
 * libu2f-server L7 workload: a U2F registration and authentication with an ES256 (P-256)
 * software token, verified by the library's own OpenSSL path.
 *
 * The harness acts as both the token and the relying party. It generates an attestation key, a
 * self-signed attestation certificate and a user credential, builds the raw registration and
 * authentication responses, and asks libu2f-server to verify them. The negative control rebuilds
 * the authentication signature with the attestation key, so the registered user key must reject it.
 */
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <u2f-server/u2f-server.h>

#define B64U_MAX 8192

static const char *ORIGIN = "https://l7.phase25.test";
static const char *APPID = "https://l7.phase25.test";
static const char *CHALLENGE = "phase25-l7-u2f-challenge-0000000000000";

static int b64u_encode(const unsigned char *in, size_t len, char *out, size_t outsz)
{
    static const char *alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t i, o = 0;
    if (outsz < (len * 4) / 3 + 4)
        return 0;
    for (i = 0; i + 2 < len; i += 3) {
        out[o++] = alphabet[in[i] >> 2];
        out[o++] = alphabet[((in[i] & 0x03) << 4) | (in[i + 1] >> 4)];
        out[o++] = alphabet[((in[i + 1] & 0x0f) << 2) | (in[i + 2] >> 6)];
        out[o++] = alphabet[in[i + 2] & 0x3f];
    }
    if (i < len) {
        out[o++] = alphabet[in[i] >> 2];
        if (i + 1 < len) {
            out[o++] = alphabet[((in[i] & 0x03) << 4) | (in[i + 1] >> 4)];
            out[o++] = alphabet[(in[i + 1] & 0x0f) << 2];
        } else {
            out[o++] = alphabet[(in[i] & 0x03) << 4];
        }
    }
    out[o] = '\0';
    return 1;
}

static int sha256(const unsigned char *data, size_t len, unsigned char out[32])
{
    return SHA256(data, len, out) != NULL;
}

static int sign_der(EC_KEY *key, const unsigned char *dgst, unsigned char **out, int *outlen)
{
    ECDSA_SIG *sig = ECDSA_do_sign(dgst, SHA256_DIGEST_LENGTH, key);
    unsigned char *der = NULL;
    int len;
    if (sig == NULL)
        return 0;
    len = i2d_ECDSA_SIG(sig, &der);
    ECDSA_SIG_free(sig);
    if (len <= 0)
        return 0;
    *out = der;
    *outlen = len;
    return 1;
}

static int public_key_bytes(EC_KEY *key, unsigned char out[65])
{
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *point = EC_KEY_get0_public_key(key);
    return EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, out, 65, NULL) == 65;
}

static int make_cert_der(EC_KEY *key, unsigned char **out, int *outlen)
{
    X509 *cert = X509_new();
    EVP_PKEY *pkey = EVP_PKEY_new();
    unsigned char *der = NULL;
    int len;
    if (cert == NULL || pkey == NULL)
        return 0;
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 7 * 24 * 3600);
    {
        /* A short CN plus a SAN large enough to push the DER certificate past 255 bytes,
         * because libu2f-server's parser derives the certificate length from a 0x30 0x82
         * header. */
        X509_NAME *name = X509_NAME_new();
        X509V3_CTX v3;
        char san[512] = "DNS:localhost,IP:127.0.0.1";
        char label[64];
        X509_EXTENSION *ext;
        memset(label, 'a', 60);
        strcpy(label + 60, ".test");
        for (int i = 0; i < 4; i++) {
            strcat(san, ",DNS:");
            strcat(san, label);
        }
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (const unsigned char *)"l7", -1, -1, 0);
        X509_set_subject_name(cert, name);
        X509_set_issuer_name(cert, name);
        X509_NAME_free(name);
        X509V3_set_ctx_nodb(&v3);
        X509V3_set_ctx(&v3, cert, cert, NULL, NULL, 0);
        ext = X509V3_EXT_conf_nid(NULL, &v3, NID_subject_alt_name, san);
        if (ext != NULL) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }
    if (EVP_PKEY_set1_EC_KEY(pkey, key) != 1) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return 0;
    }
    X509_set_pubkey(cert, pkey);
    if (X509_sign(cert, pkey, EVP_sha256()) <= 0) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return 0;
    }
    len = i2d_X509(cert, &der);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    if (len <= 0)
        return 0;
    *out = der;
    *outlen = len;
    return 1;
}

static int build_client_data(const char *typ, const unsigned char *challenge, size_t challenge_len,
                             char *out, size_t outsz, char *b64, size_t b64sz)
{
    char raw[512];
    int n = snprintf(raw, sizeof(raw),
                     "{\"typ\":\"%s\",\"challenge\":\"%.*s\",\"origin\":\"%s\"}",
                     typ, (int)challenge_len, (const char *)challenge, ORIGIN);
    if (n < 0 || (size_t)n >= sizeof(raw))
        return 0;
    memcpy(out, raw, (size_t)n);
    out[n] = '\0';
    return b64u_encode((const unsigned char *)raw, (size_t)n, b64, b64sz);
}

int main(int argc, char **argv)
{
    EC_KEY *att_key = NULL, *user_key = NULL;
    unsigned char *cert_der = NULL;
    int cert_der_len = 0;
    unsigned char user_pub[65], key_handle[32];
    unsigned char app_hash[32], client_hash[32], digest[32], buffer[512];
    unsigned char *reg_sig = NULL, *auth_sig = NULL, *bad_sig = NULL;
    int reg_sig_len = 0, auth_sig_len = 0, bad_sig_len = 0;
    unsigned char reg_data[4096], auth_data[4096];
    size_t reg_len = 0, auth_len = 0;
    char reg_b64[B64U_MAX], client_b64[B64U_MAX];
    char client_json[512], reg_json[8192], auth_json[8192];
    char challenge_b64[B64U_MAX];
    char *client_reg_b64 = NULL, *client_auth_b64 = NULL;
    u2fs_ctx_t *ctx = NULL;
    u2fs_reg_res_t *reg = NULL;
    u2fs_auth_res_t *auth = NULL;
    const char *handle;
    const char *pub;
    u2fs_rc rc;
    int ok = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("libu2f-server-l7-harness\n");
            return 0;
        }
    }

    att_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    user_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (att_key == NULL || user_key == NULL ||
        EC_KEY_generate_key(att_key) != 1 || EC_KEY_generate_key(user_key) != 1 ||
        !public_key_bytes(user_key, user_pub) ||
        RAND_bytes(key_handle, sizeof(key_handle)) != 1 ||
        !make_cert_der(att_key, &cert_der, &cert_der_len))
        goto done;

    /* A fixed 43-character base64url challenge (32 raw bytes, no padding). */
    unsigned char raw_challenge[32];
    RAND_bytes(raw_challenge, sizeof(raw_challenge));
    if (!b64u_encode(raw_challenge, sizeof(raw_challenge), challenge_b64, sizeof(challenge_b64)))
        goto done;

    client_reg_b64 = client_b64;
    client_auth_b64 = malloc(B64U_MAX);
    if (client_auth_b64 == NULL)
        goto done;

    if (u2fs_global_init(0) != U2FS_OK || u2fs_init(&ctx) != U2FS_OK ||
        u2fs_set_origin(ctx, ORIGIN) != U2FS_OK || u2fs_set_appid(ctx, APPID) != U2FS_OK ||
        u2fs_set_challenge(ctx, challenge_b64) != U2FS_OK)
        goto done;

    /* Registration response. */
    if (!build_client_data("navigator.id.finishEnrollment", (unsigned char *)challenge_b64,
                           43, client_json, sizeof(client_json), client_reg_b64, B64U_MAX))
        goto done;
    if (!sha256((const unsigned char *)APPID, strlen(APPID), app_hash) ||
        !sha256((const unsigned char *)client_json, strlen(client_json), client_hash))
        goto done;
    size_t used = 0;
    buffer[used++] = 0x00;
    memcpy(buffer + used, app_hash, 32); used += 32;
    memcpy(buffer + used, client_hash, 32); used += 32;
    memcpy(buffer + used, key_handle, sizeof(key_handle)); used += sizeof(key_handle);
    memcpy(buffer + used, user_pub, sizeof(user_pub)); used += sizeof(user_pub);
    if (!sha256(buffer, used, digest) || !sign_der(att_key, digest, &reg_sig, &reg_sig_len))
        goto done;

    reg_data[reg_len++] = 0x05;
    memcpy(reg_data + reg_len, user_pub, sizeof(user_pub)); reg_len += sizeof(user_pub);
    reg_data[reg_len++] = (unsigned char)sizeof(key_handle);
    memcpy(reg_data + reg_len, key_handle, sizeof(key_handle)); reg_len += sizeof(key_handle);
    memcpy(reg_data + reg_len, cert_der, (size_t)cert_der_len); reg_len += (size_t)cert_der_len;
    memcpy(reg_data + reg_len, reg_sig, (size_t)reg_sig_len); reg_len += (size_t)reg_sig_len;
    if (!b64u_encode(reg_data, reg_len, reg_b64, sizeof(reg_b64)))
        goto done;
    snprintf(reg_json, sizeof(reg_json), "{\"registrationData\":\"%s\",\"clientData\":\"%s\"}",
             reg_b64, client_reg_b64);

    rc = u2fs_registration_verify(ctx, reg_json, &reg);
    if (rc != U2FS_OK) {
        printf("u2f_register=failed:%d\n", (int)rc);
        goto done;
    }
    printf("u2f_register=ok\n");

    handle = u2fs_get_registration_keyHandle(reg);
    pub = u2fs_get_registration_publicKey(reg);
    if (handle == NULL || pub == NULL ||
        u2fs_set_keyHandle(ctx, handle) != U2FS_OK ||
        u2fs_set_publicKey(ctx, (const unsigned char *)pub) != U2FS_OK) {
        printf("u2f_register=failed:result\n");
        goto done;
    }

    /* Authentication response signed by the registered user key. */
    if (!build_client_data("navigator.id.getAssertion", (unsigned char *)challenge_b64, 43,
                           client_json, sizeof(client_json), client_auth_b64, B64U_MAX))
        goto done;
    if (!sha256((const unsigned char *)client_json, strlen(client_json), client_hash))
        goto done;
    used = 0;
    memcpy(buffer + used, app_hash, 32); used += 32;
    buffer[used++] = 0x01;
    buffer[used++] = 0x00; buffer[used++] = 0x00;
    buffer[used++] = 0x00; buffer[used++] = 0x01;
    memcpy(buffer + used, client_hash, 32); used += 32;
    if (!sha256(buffer, used, digest) || !sign_der(user_key, digest, &auth_sig, &auth_sig_len))
        goto done;

    auth_data[0] = 0x01;
    auth_data[1] = 0x00; auth_data[2] = 0x00; auth_data[3] = 0x00; auth_data[4] = 0x01;
    memcpy(auth_data + 5, auth_sig, (size_t)auth_sig_len);
    auth_len = 5 + (size_t)auth_sig_len;
    if (!b64u_encode(auth_data, auth_len, reg_b64, sizeof(reg_b64)))
        goto done;
    snprintf(auth_json, sizeof(auth_json),
             "{\"signatureData\":\"%s\",\"clientData\":\"%s\",\"keyHandle\":\"%s\"}",
             reg_b64, client_auth_b64, handle);

    rc = u2fs_authentication_verify(ctx, auth_json, &auth);
    if (rc != U2FS_OK) {
        printf("u2f_authenticate=failed:%d\n", (int)rc);
        goto done;
    }
    {
        u2fs_rc verified = 0;
        uint32_t counter = 0;
        uint8_t presence = 0;
        u2fs_get_authentication_result(auth, &verified, &counter, &presence);
        if (verified != U2FS_OK || presence != 1 || counter != 1) {
            printf("u2f_authenticate=failed:result\n");
            goto done;
        }
    }
    printf("u2f_authenticate=ok\n");

    /* Negative control: the same digest signed by the attestation key must be rejected. */
    if (!sign_der(att_key, digest, &bad_sig, &bad_sig_len))
        goto done;
    memcpy(auth_data + 5, bad_sig, (size_t)bad_sig_len);
    auth_len = 5 + (size_t)bad_sig_len;
    if (!b64u_encode(auth_data, auth_len, reg_b64, sizeof(reg_b64)))
        goto done;
    snprintf(auth_json, sizeof(auth_json),
             "{\"signatureData\":\"%s\",\"clientData\":\"%s\",\"keyHandle\":\"%s\"}",
             reg_b64, client_auth_b64, handle);
    u2fs_auth_res_t *bad = NULL;
    rc = u2fs_authentication_verify(ctx, auth_json, &bad);
    if (bad != NULL)
        u2fs_free_auth_res(bad);
    if (rc == U2FS_OK) {
        printf("altered_signature=accepted\n");
        goto done;
    }
    printf("altered_signature=rejected\n");
    ok = 1;

done:
    if (!ok && ctx == NULL)
        printf("u2f_register=failed:init\n");
    if (auth != NULL)
        u2fs_free_auth_res(auth);
    if (reg != NULL)
        u2fs_free_reg_res(reg);
    if (ctx != NULL) {
        u2fs_done(ctx);
        u2fs_global_done();
    }
    free(client_auth_b64);
    free(reg_sig);
    free(auth_sig);
    free(bad_sig);
    free(cert_der);
    if (att_key != NULL)
        EC_KEY_free(att_key);
    if (user_key != NULL)
        EC_KEY_free(user_key);
    return ok ? 0 : 3;
}
