/*
 * getdns L7 workload: a DNS-over-TLS query for a fixture zone against a loopback TLS resolver,
 * answered with an exact A record, and a wrong-CA negative control.
 *
 * The resolver side is a real libssl handshake and a minimal DNS responder; getdns is the
 * resolver client and must verify the fixture CA before it accepts the answer. Run with
 * `--ca <pem>`; the workload passes the fixture CA for the positive case and an unrelated CA
 * for the negative case, and the marker distinguishes them.
 */
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "l7_local_tls.h"

typedef struct {
    int queries;
} dns_state;

static int dns_handler(SSL *ssl, void *opaque)
{
    dns_state *state = (dns_state *)opaque;
    unsigned char query[4096];
    unsigned char reply[4096];
    unsigned char lenbuf[2];
    size_t qlen;

    if (!l7_read_full(ssl, lenbuf, 2))
        return -1;
    qlen = ((size_t)lenbuf[0] << 8) | (size_t)lenbuf[1];
    if (qlen < 12 || qlen > sizeof(query))
        return -1;
    if (!l7_read_full(ssl, query, qlen))
        return -1;

    /* The question ends after the qname and its 4-byte type/class fields. */
    size_t question = 12;
    while (question < qlen && query[question] != 0)
        question += (size_t)query[question] + 1;
    if (question + 1 + 4 > qlen)
        return -1;
    question += 1 + 4;

    memcpy(reply, query, question);
    reply[2] = 0x81;                 /* QR, RD */
    reply[3] = 0x80;                 /* RA */
    reply[6] = 0x00; reply[7] = 0x01; /* ANCOUNT = 1 */
    reply[8] = 0x00; reply[9] = 0x00;
    reply[10] = 0x00; reply[11] = 0x00;
    size_t used = question;
    static const unsigned char answer[] = {
        0xc0, 0x0c,              /* name: pointer to the question */
        0x00, 0x01,              /* TYPE A */
        0x00, 0x01,              /* CLASS IN */
        0x00, 0x00, 0x00, 0x3c,  /* TTL 60 */
        0x00, 0x04,              /* RDLENGTH */
        192, 0, 2, 53,           /* fixture address */
    };
    memcpy(reply + used, answer, sizeof(answer));
    used += sizeof(answer);
    reply[0] = query[0];
    reply[1] = query[1];

    lenbuf[0] = (unsigned char)(used >> 8);
    lenbuf[1] = (unsigned char)(used & 0xff);
    if (!l7_write_all(ssl, lenbuf, 2))
        return -1;
    if (!l7_write_all(ssl, reply, used))
        return -1;
    state->queries++;
    return 0;
}

static int spki_sha256(const char *path, unsigned char out[32])
{
    BIO *bio = BIO_new_file(path, "r");
    X509 *cert = NULL;
    X509_PUBKEY *pub;
    unsigned char *der = NULL, *p;
    int len;
    int ok = 0;
    if (bio == NULL)
        return 0;
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (cert == NULL)
        return 0;
    pub = X509_get_X509_PUBKEY(cert);
    len = i2d_X509_PUBKEY(pub, NULL);
    if (len > 0 && (der = malloc((size_t)len)) != NULL) {
        p = der;
        if (i2d_X509_PUBKEY(pub, &p) == len && SHA256(der, (size_t)len, out) != NULL)
            ok = 1;
        free(der);
    }
    X509_free(cert);
    return ok;
}

static int fixture_address(getdns_dict *response, char *out, size_t outsz)
{
    getdns_list *tree = NULL, *answers = NULL;
    getdns_dict *reply = NULL, *rr = NULL, *rdata = NULL;
    getdns_bindata *addr = NULL;

    if (getdns_dict_get_list(response, "replies_tree", &tree) != GETDNS_RETURN_GOOD ||
        getdns_list_get_dict(tree, 0, &reply) != GETDNS_RETURN_GOOD ||
        getdns_dict_get_list(reply, "answer", &answers) != GETDNS_RETURN_GOOD ||
        getdns_list_get_dict(answers, 0, &rr) != GETDNS_RETURN_GOOD ||
        getdns_dict_get_dict(rr, "rdata", &rdata) != GETDNS_RETURN_GOOD ||
        getdns_dict_get_bindata(rdata, "ipv4_address", &addr) != GETDNS_RETURN_GOOD ||
        addr->size != 4)
        return 0;
    snprintf(out, outsz, "%u.%u.%u.%u", addr->data[0], addr->data[1],
             addr->data[2], addr->data[3]);
    return 1;
}

int main(int argc, char **argv)
{
    const char *cert = NULL, *key = NULL, *ca = NULL, *pin_cert = NULL;
    l7_tls_server server;
    dns_state state = {0};
    getdns_context *ctx = NULL;
    getdns_list *upstreams = NULL;
    getdns_dict *server_dict = NULL;
    getdns_dict *response = NULL;
    getdns_bindata address = {4, (uint8_t *)"\x7f\x00\x00\x01"};
    getdns_bindata auth_name = {9, (uint8_t *)"127.0.0.1"};
    getdns_bindata ipv4_type = {4, (uint8_t *)"IPv4"};
    char answer[64] = "";
    int n = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("getdns-l7-harness\n");
            return 0;
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key = argv[++i];
        } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            ca = argv[++i];
        } else if (strcmp(argv[i], "--pin-cert") == 0 && i + 1 < argc) {
            pin_cert = argv[++i];
        }
    }
    signal(SIGPIPE, SIG_IGN);

    if (cert == NULL || key == NULL || ca == NULL) {
        fprintf(stderr, "usage: %s --cert CRT --key KEY --ca CA [--pin-cert CERT]\n", argv[0]);
        return 2;
    }
    if (pin_cert == NULL)
        pin_cert = cert;

    if (l7_tls_server_start(&server, cert, key, dns_handler, &state, 4) != 0) {
        fprintf(stderr, "the local DoT listener did not start\n");
        return 2;
    }

    if (getdns_context_create(&ctx, 0) != GETDNS_RETURN_GOOD) {
        fprintf(stderr, "getdns context creation failed\n");
        l7_tls_server_stop(&server);
        return 2;
    }
    getdns_context_set_dns_transport(ctx, GETDNS_TRANSPORT_TLS_ONLY_KEEP_CONNECTIONS_OPEN);
    getdns_context_set_tls_authentication(ctx, GETDNS_AUTHENTICATION_REQUIRED);
    if (getdns_context_set_tls_ca_file(ctx, ca) != GETDNS_RETURN_GOOD) {
        fprintf(stderr, "getdns refused the CA file\n");
        getdns_context_destroy(ctx);
        l7_tls_server_stop(&server);
        return 2;
    }

    upstreams = getdns_list_create_with_context(ctx);
    server_dict = getdns_dict_create_with_context(ctx);
    if (upstreams == NULL || server_dict == NULL)
        return 2;
    getdns_dict_set_bindata(server_dict, "address_type", &ipv4_type);
    getdns_dict_set_bindata(server_dict, "address_data", &address);
    getdns_dict_set_int(server_dict, "port", 853);
    getdns_dict_set_int(server_dict, "tls_port", server.port);
    getdns_dict_set_bindata(server_dict, "tls_auth_name", &auth_name);
    {
        unsigned char pin[32];
        getdns_bindata digest = {6, (uint8_t *)"sha256"};
        getdns_bindata value = {32, pin};
        getdns_list *pinset;
        getdns_dict *entry;
        if (!spki_sha256(pin_cert, pin)) {
            fprintf(stderr, "the pin certificate could not be read\n");
            return 2;
        }
        pinset = getdns_list_create_with_context(ctx);
        entry = getdns_dict_create_with_context(ctx);
        if (pinset == NULL || entry == NULL)
            return 2;
        getdns_dict_set_bindata(entry, "digest", &digest);
        getdns_dict_set_bindata(entry, "value", &value);
        getdns_list_set_dict(pinset, 0, entry);
        getdns_dict_set_list(server_dict, "tls_pubkey_pinset", pinset);
    }
    getdns_list_set_dict(upstreams, 0, server_dict);
    if (getdns_context_set_upstream_recursive_servers(ctx, upstreams) !=
        GETDNS_RETURN_GOOD) {
        fprintf(stderr, "getdns refused the upstream list\n");
        getdns_dict_destroy(server_dict);
        getdns_list_destroy(upstreams);
        getdns_context_destroy(ctx);
        l7_tls_server_stop(&server);
        return 2;
    }

    getdns_return_t rc = getdns_general_sync(ctx, "l7.phase25.test", GETDNS_RRTYPE_A,
                                             NULL, &response);
    if (rc == GETDNS_RETURN_GOOD && response != NULL && fixture_address(response, answer,
                                                                      sizeof(answer))) {
        printf("dot_query=answered\n");
        printf("answer=%s\n", answer);
        n = strcmp(answer, "192.0.2.53") == 0 ? 0 : 3;
    } else {
        printf("dot_query=rejected\n");
        fprintf(stderr, "getdns_rc=%d %s\n", (int)rc, getdns_get_errorstr_by_id(rc));
        n = 0;
    }

    if (response != NULL)
        getdns_dict_destroy(response);
    getdns_dict_destroy(server_dict);
    getdns_list_destroy(upstreams);
    getdns_context_destroy(ctx);
    l7_tls_server_stop(&server);
    return n == 0 ? 0 : n;
}
