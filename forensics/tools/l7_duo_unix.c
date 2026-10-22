/*
 * duo_unix (libduo) L7 workload: a Duo authentication against a loopback HTTPS endpoint that
 * validates libduo's own HMAC-SHA1 request signature, plus a corrupted-credential control.
 *
 * The server recomputes the canonical request signature with the subject libcrypto and returns
 * 200 only when libduo's Authorization header matches. The positive run must authenticate
 * (`hmac_vector=ok`, `duo_login=ok`); the negative run opens the handle with a corrupted secret
 * and the same server must reject it (`corrupt_signature=rejected`).
 */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "duo.h"
#include "l7_local_tls.h"

static const char *IKEY = "DIXYZV6YM8IFYVWBINCA";
static const char *SKEY = "yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo";

typedef struct {
    int good_hmac;
    int bad_hmac;
} duo_state;

static void put_i32(unsigned char *p, int32_t v)
{
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
    p[2] = (unsigned char)((v >> 16) & 0xff);
    p[3] = (unsigned char)((v >> 24) & 0xff);
}

static void bson_str(unsigned char *doc, size_t *off, const char *key, const char *value)
{
    size_t klen = strlen(key) + 1;
    int32_t vlen = (int32_t)strlen(value) + 1;
    doc[(*off)++] = 0x02;
    memcpy(doc + *off, key, klen);
    *off += klen;
    put_i32(doc + *off, vlen);
    *off += 4;
    memcpy(doc + *off, value, (size_t)vlen);
    *off += (size_t)vlen;
}

static void bson_finish(unsigned char *doc, size_t start, size_t *off)
{
    doc[(*off)++] = 0x00;
    put_i32(doc + start, (int32_t)(*off - start));
}

static size_t bson_inner(unsigned char *doc, const char *result, const char *status,
                         int preauth)
{
    size_t off = 4;
    bson_str(doc, &off, "result", result);
    if (status != NULL)
        bson_str(doc, &off, "status", status);
    if (preauth) {
        size_t klen = strlen("factors") + 1;
        bson_str(doc, &off, "prompt", "Choose a factor");
        doc[off++] = 0x03;
        memcpy(doc + off, "factors", klen);
        off += klen;
        put_i32(doc + off, 5);
        off += 4;
        doc[off++] = 0x00;
    }
    bson_finish(doc, 0, &off);
    return off;
}

static size_t bson_outer(unsigned char *doc, const unsigned char *inner, size_t inner_len)
{
    size_t off = 4;
    size_t klen = strlen("response") + 1;
    bson_str(doc, &off, "stat", "OK");
    doc[off++] = 0x03;
    memcpy(doc + off, "response", klen);
    off += klen;
    /* The embedded document's value is the whole document, including its own length. */
    memcpy(doc + off, inner, inner_len);
    off += inner_len;
    bson_finish(doc, 0, &off);
    return off;
}

static int b64_decode(const char *in, unsigned char *out, size_t outsz)
{
    static const signed char table[] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    };
    size_t o = 0;
    int acc = 0, bits = 0;
    for (const char *p = in; *p != '\0'; p++) {
        int v;
        if (*p == '=' || isspace((unsigned char)*p))
            continue;
        if ((unsigned char)*p >= sizeof(table))
            return -1;
        v = table[(unsigned char)*p];
        if (v < 0)
            return -1;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= outsz)
                return -1;
            out[o++] = (unsigned char)((acc >> bits) & 0xff);
        }
    }
    return (int)o;
}

static void hex_encode(const unsigned char *in, size_t len, char *out)
{
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static int read_line(SSL *ssl, char *buf, size_t sz)
{
    size_t used = 0;
    while (used + 1 < sz) {
        char c;
        if (!l7_read_full(ssl, &c, 1))
            return 0;
        buf[used++] = c;
        if (c == '\n')
            break;
    }
    buf[used] = '\0';
    return 1;
}

static int verify_request(const char *method, const char *host, const char *path,
                          const char *qs, const char *auth, duo_state *state)
{
    unsigned char decoded[512];
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int maclen = 0;
    char expected[EVP_MAX_MD_SIZE * 2 + 1];
    char canonical[8192];
    int n = b64_decode(auth, decoded, sizeof(decoded));
    if (n <= 0 || (size_t)n >= sizeof(decoded))
        return 0;
    decoded[n] = '\0';
    char *colon = strchr((char *)decoded, ':');
    if (colon == NULL)
        return 0;
    *colon = '\0';
    if (strcmp((char *)decoded, IKEY) != 0)
        return 0;
    snprintf(canonical, sizeof(canonical), "%s\n%s\n%s\n%s", method, host, path, qs);
    if (HMAC(EVP_sha1(), SKEY, (int)strlen(SKEY),
             (const unsigned char *)canonical, strlen(canonical), mac, &maclen) == NULL)
        return 0;
    hex_encode(mac, maclen, expected);
    if (strcmp(colon + 1, expected) == 0) {
        state->good_hmac++;
        return 1;
    }
    state->bad_hmac++;
    return 0;
}

static char *prompt_fn(void *arg, const char *prompt, char *buf, size_t bufsz)
{
    (void)arg;
    (void)prompt;
    snprintf(buf, bufsz, "push");
    return buf;
}

static int https_handler(SSL *ssl, void *opaque)
{
    duo_state *state = (duo_state *)opaque;
    for (;;) {
        char line[2048], method[16], target[512], auth[1024], host[256];
        long content_length = 0;
        method[0] = target[0] = auth[0] = '\0';
        snprintf(host, sizeof(host), "localhost");
        if (!read_line(ssl, line, sizeof(line))) {
            if (state->good_hmac > 0)
                return 0;
            return -1;
        }
        if (sscanf(line, "%15s %511s", method, target) != 2)
            return -1;
        for (;;) {
            if (!read_line(ssl, line, sizeof(line)))
                return -1;
            if (strcmp(line, "\r\n") == 0)
                break;
            if (strncasecmp(line, "Authorization: Basic ", 21) == 0) {
                char *v = line + 21;
                v[strcspn(v, "\r\n")] = '\0';
                snprintf(auth, sizeof(auth), "%s", v);
            } else if (strncasecmp(line, "Host: ", 6) == 0) {
                char *v = line + 6;
                v[strcspn(v, "\r\n")] = '\0';
                char *colon = strchr(v, ':');
                if (colon != NULL)
                    *colon = '\0';
                snprintf(host, sizeof(host), "%s", v);
            } else if (strncasecmp(line, "Content-Length:", 15) == 0) {
                content_length = strtol(line + 15, NULL, 10);
            }
        }
        char body[8192];
        size_t body_len = 0;
        if (content_length > 0) {
            if ((size_t)content_length >= sizeof(body))
                return -1;
            if (!l7_read_full(ssl, body, (size_t)content_length))
                return -1;
            body_len = (size_t)content_length;
        }
        body[body_len] = '\0';
        const char *qs = (strcmp(method, "GET") == 0) ? "" : body;
        char path[512];
        snprintf(path, sizeof(path), "%s", target);

        int authorised = verify_request(method, host, path, qs, auth, state);
        unsigned char inner[512], outer[1024];
        size_t inner_len, outer_len;
        if (!authorised) {
            const char *err = "unauthorized";
            snprintf((char *)outer, sizeof(outer),
                     "HTTP/1.1 401 Unauthorized\r\nContent-Length: %zu\r\n"
                     "Content-Type: text/plain\r\n\r\n%s", strlen(err), err);
            l7_write_all(ssl, outer, strlen((char *)outer));
            return 0;
        }
        if (strstr(path, "preauth.bson") != NULL) {
            inner_len = bson_inner(inner, "auth", NULL, 1);
        } else {
            inner_len = bson_inner(inner, "allow", "phase25-l7-duo", 0);
        }
        outer_len = bson_outer(outer, inner, inner_len);
        {
            char response[2048];
            int hlen = snprintf(response, sizeof(response),
                                "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n"
                                "Content-Type: application/bson\r\nConnection: close\r\n\r\n",
                                outer_len);
            memcpy(response + hlen, outer, outer_len);
            l7_write_all(ssl, response, (size_t)hlen + outer_len);
        }
        return 0;
    }
}

int main(int argc, char **argv)
{
    const char *cert = NULL, *key = NULL, *ca = NULL;
    int corrupt = 0;
    l7_tls_server server;
    duo_state state = {0, 0};
    char host[128];
    char secret[128];
    duo_t *duo = NULL;
    duo_code_t rc;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("duo_unix-l7-harness\n");
            return 0;
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key = argv[++i];
        } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            ca = argv[++i];
        } else if (strcmp(argv[i], "--corrupt") == 0) {
            corrupt = 1;
        }
    }
    if (cert == NULL || key == NULL || ca == NULL) {
        fprintf(stderr, "usage: %s --cert CRT --key KEY --ca CA [--corrupt]\n", argv[0]);
        return 2;
    }
    if (l7_tls_server_start(&server, cert, key, https_handler, &state, 8) != 0) {
        fprintf(stderr, "the local HTTPS listener did not start\n");
        return 2;
    }

    snprintf(host, sizeof(host), "localhost:%d", server.port);
    snprintf(secret, sizeof(secret), "%s", SKEY);
    if (corrupt)
        secret[strlen(secret) - 1] = 'X';

    duo = duo_open(host, IKEY, secret, "l7-duo", ca, 10000, NULL);
    if (duo == NULL) {
        fprintf(stderr, "duo_open failed\n");
        l7_tls_server_stop(&server);
        return 2;
    }
    duo_set_conv_funcs(duo, prompt_fn, NULL, NULL);
    rc = duo_login(duo, "phase25", NULL, DUO_FLAG_SYNC, NULL, 1);
    duo = duo_close(duo);
    l7_tls_server_stop(&server);

    printf("hmac_verified=%d\n", state.good_hmac);
    printf("hmac_rejected=%d\n", state.bad_hmac);
    if (corrupt) {
        printf("corrupt_signature=%s\n", rc == DUO_OK ? "accepted" : "rejected");
        return rc == DUO_OK ? 3 : 0;
    }
    if (rc == DUO_OK && state.good_hmac == 2) {
        printf("hmac_vector=ok\n");
        printf("duo_login=ok\n");
        return 0;
    }
    printf("duo_login=failed:%d\n", (int)rc);
    return 3;
}
