/*
 * Phase-25 L7 workload for the library-only `libcoap` family.
 *
 * libcoap ships no program of its own. This harness runs a CoAP server and a
 * CoAP client in one process over a loopback TLS (CoAP over TLS) connection,
 * using libcoap's OpenSSL DTLS/TLS backend. The server answers a GET on /l7
 * with a fixed payload, and the client must receive exactly those bytes.
 *
 * A second client that trusts only an unrelated CA must not complete the TLS
 * handshake and must never receive the payload.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <coap3/coap.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char PAYLOAD[] = "phase25-l7-coap-response";
static const unsigned char TOKEN[] = { 0x4c, 0x37, 0x00, 0x01 };

static int g_got;
static int g_match;

static void get_handler(coap_resource_t *resource, coap_session_t *session,
                        const coap_pdu_t *request, const coap_string_t *query,
                        coap_pdu_t *response)
{
    (void)resource;
    (void)session;
    (void)request;
    (void)query;
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data(response, (size_t)strlen(PAYLOAD), (const uint8_t *)PAYLOAD);
}

static coap_response_t response_handler(coap_session_t *session,
                                        const coap_pdu_t *sent,
                                        const coap_pdu_t *received,
                                        const coap_mid_t id)
{
    const uint8_t *data = NULL;
    size_t len = 0;

    (void)session;
    (void)sent;
    (void)id;
    if (coap_pdu_get_code(received) != COAP_RESPONSE_CODE_CONTENT)
        return COAP_RESPONSE_OK;
    if (!coap_get_data(received, &len, &data))
        return COAP_RESPONSE_OK;
    g_got = 1;
    g_match = (len == strlen(PAYLOAD) && memcmp(data, PAYLOAD, len) == 0);
    return COAP_RESPONSE_OK;
}

static void set_loopback(coap_address_t *addr, uint16_t port)
{
    coap_address_init(addr);
    addr->addr.sin.sin_family = AF_INET;
    addr->addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr->addr.sin.sin_port = htons(port);
    addr->size = sizeof(struct sockaddr_in);
}

static uint16_t listener_port(int fd)
{
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);

    if (getsockname(fd, (struct sockaddr *)&sin, &len) != 0)
        return 0;
    return ntohs(sin.sin_port);
}

static int free_port(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sin;
    int one = 1;
    uint16_t port;

    if (fd < 0)
        return 0;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0 || listen(fd, 1) != 0) {
        close(fd);
        return 0;
    }
    port = listener_port(fd);
    close(fd);
    return (int)port;
}

static coap_dtls_pki_t server_pki(const char *cert, const char *key)
{
    coap_dtls_pki_t pki;

    memset(&pki, 0, sizeof(pki));
    pki.version = COAP_DTLS_PKI_SETUP_VERSION;
    pki.verify_peer_cert = 0;
    pki.check_common_ca = 0;
    pki.allow_self_signed = 0;
    pki.cert_chain_validation = 0;
    pki.pki_key.key_type = COAP_PKI_KEY_PEM;
    pki.pki_key.key.pem.ca_file = NULL;
    pki.pki_key.key.pem.public_cert = cert;
    pki.pki_key.key.pem.private_key = key;
    return pki;
}

static coap_dtls_pki_t client_pki(const char *ca)
{
    coap_dtls_pki_t pki;

    memset(&pki, 0, sizeof(pki));
    pki.version = COAP_DTLS_PKI_SETUP_VERSION;
    pki.verify_peer_cert = 1;
    pki.check_common_ca = 1;
    pki.allow_self_signed = 0;
    pki.cert_chain_validation = 1;
    pki.cert_chain_verify_depth = 2;
    pki.pki_key.key_type = COAP_PKI_KEY_PEM;
    pki.pki_key.key.pem.ca_file = ca;
    pki.pki_key.key.pem.public_cert = NULL;
    pki.pki_key.key.pem.private_key = NULL;
    return pki;
}

int main(int argc, char **argv)
{
    const char *cert = NULL, *key = NULL, *ca = NULL, *other_ca = NULL;
    int port, waited = 0;
    int ok = 0;
    coap_context_t *sctx = NULL, *cctx = NULL, *nctx = NULL;
    coap_endpoint_t *endpoint = NULL;
    coap_resource_t *resource = NULL;
    coap_dtls_pki_t spki;
    coap_address_t listen_addr, dst;
    int neg_ok = 0;

    coap_set_log_level(COAP_LOG_EMERG);
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--version")) {
            printf("libcoap-l7-harness\n");
            return 0;
        } else if (!strcmp(argv[i], "--cert") && i + 1 < argc) {
            cert = argv[++i];
        } else if (!strcmp(argv[i], "--key") && i + 1 < argc) {
            key = argv[++i];
        } else if (!strcmp(argv[i], "--ca") && i + 1 < argc) {
            ca = argv[++i];
        } else if (!strcmp(argv[i], "--other-ca") && i + 1 < argc) {
            other_ca = argv[++i];
        }
    }
    if (cert == NULL || key == NULL || ca == NULL || other_ca == NULL) {
        fprintf(stderr, "usage: %s --cert F --key F --ca F --other-ca F\n", argv[0]);
        return 2;
    }

    port = free_port();
    if (port <= 0)
        return 1;

    sctx = coap_new_context(NULL);
    if (sctx == NULL)
        return 1;
    spki = server_pki(cert, key);
    if (!coap_context_set_pki(sctx, &spki))
        goto done;
    resource = coap_resource_init(coap_make_str_const("l7"), 0);
    if (resource == NULL)
        goto done;
    coap_register_handler(resource, COAP_REQUEST_GET, get_handler);
    coap_add_resource(sctx, resource);
    set_loopback(&listen_addr, (uint16_t)port);
    endpoint = coap_new_endpoint(sctx, &listen_addr, COAP_PROTO_TLS);
    if (endpoint == NULL)
        goto done;

    cctx = coap_new_context(NULL);
    if (cctx == NULL)
        goto done;
    coap_register_response_handler(cctx, response_handler);
    set_loopback(&dst, (uint16_t)port);

    /* Pump the server until the good client has completed its exchange. */
    {
        coap_dtls_pki_t pki = client_pki(ca);
        coap_session_t *session = coap_new_client_session_pki(cctx, NULL, &dst,
                                                             COAP_PROTO_TLS, &pki);
        coap_pdu_t *pdu;

        if (session == NULL)
            goto done;
        pdu = coap_new_pdu(COAP_MESSAGE_CON, COAP_REQUEST_GET, session);
        if (pdu == NULL || !coap_add_token(pdu, sizeof(TOKEN), TOKEN) ||
            !coap_add_option(pdu, COAP_OPTION_URI_PATH, 2, (const uint8_t *)"l7") ||
            coap_send(session, pdu) == COAP_INVALID_MID) {
            coap_session_release(session);
            goto done;
        }
        while (!g_got && waited < 5000) {
            coap_io_process(sctx, 10);
            coap_io_process(cctx, 10);
            waited += 10;
        }
        coap_session_release(session);
    }
    if (!g_got || !g_match) {
        fprintf(stderr, "libcoap: no matching CoAP payload over TLS\n");
        goto done;
    }
    printf("coap_tls=ok\n");
    printf("payload=%s\n", PAYLOAD);

    /* Negative control: a client trusting an unrelated CA must not get a response. */
    nctx = coap_new_context(NULL);
    if (nctx == NULL)
        goto done;
    coap_register_response_handler(nctx, response_handler);
    {
        coap_dtls_pki_t pki = client_pki(other_ca);
        coap_session_t *session;

        g_got = 0;
        g_match = 0;
        session = coap_new_client_session_pki(nctx, NULL, &dst,
                                                             COAP_PROTO_TLS, &pki);
        coap_pdu_t *pdu;

        if (session == NULL) {
            neg_ok = 1;
        } else {
            pdu = coap_new_pdu(COAP_MESSAGE_CON, COAP_REQUEST_GET, session);
            if (pdu == NULL || !coap_add_token(pdu, sizeof(TOKEN), TOKEN) ||
                !coap_add_option(pdu, COAP_OPTION_URI_PATH, 2, (const uint8_t *)"l7") ||
                coap_send(session, pdu) == COAP_INVALID_MID)
                neg_ok = 1;
            waited = 0;
            while (!g_got && waited < 1500) {
                coap_io_process(sctx, 10);
                coap_io_process(nctx, 10);
                waited += 10;
            }
            if (!g_got)
                neg_ok = 1;
            coap_session_release(session);
        }
    }
    if (!neg_ok) {
        fprintf(stderr, "libcoap: the unrelated CA completed the TLS handshake\n");
        goto done;
    }
    printf("negative=rejected\n");
    ok = 1;
 done:
    if (nctx != NULL)
        coap_free_context(nctx);
    if (cctx != NULL)
        coap_free_context(cctx);
    if (sctx != NULL)
        coap_free_context(sctx);
    return ok ? 0 : 1;
}
