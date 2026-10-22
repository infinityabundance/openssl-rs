/*
 * Phase-25 L7 workload for the `sofia-sip` family.
 *
 * sofia-sip's OpenSSL consumer path is tport's TLS transport
 * (libsofia-sip-ua/tport/tport_tls.c: SSL_CTX_use_certificate_file/
 * SSL_CTX_use_PrivateKey_file/SSL_CTX_load_verify_locations/SSL_connect/
 * SSL_accept). This harness binds a TLS server and a TLS client tport on
 * loopback, sends one SIP MESSAGE with a payload, and requires the peer's
 * tport receive callback to see that exact payload. The negative control
 * repeats the send with a client certificate directory whose cafile.pem is an
 * unrelated CA: the client tport has TPTAG_TLS_VERIFY_PEER set, so the
 * handshake must fail and no message may arrive.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/su.h>
#include <sofia-sip/su_wait.h>
#include <sofia-sip/msg.h>
#include <sofia-sip/tport.h>
#include <sofia-sip/tport_tag.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char PAYLOAD[] = "sofia-sip-l7-payload";

struct stack {
    int received;
    int error;
    char payload[256];
};

static void stack_recv(tp_stack_t *stack, tport_t *tp, msg_t *msg,
                       tp_magic_t *magic, su_time_t received)
{
    struct stack *s = (struct stack *)stack;
    sip_t const *sip = (sip_t const *)msg_public(msg, NULL);

    (void)tp;
    (void)magic;
    (void)received;
    if (sip != NULL && sip->sip_payload != NULL) {
        size_t n = sip->sip_payload->pl_len;

        if (n >= sizeof(s->payload))
            n = sizeof(s->payload) - 1;
        memcpy(s->payload, sip->sip_payload->pl_data, n);
        s->payload[n] = '\0';
        s->received = 1;
    }
    msg_destroy(msg);
}

static void stack_error(tp_stack_t *stack, tport_t *tp, int errcode, char const *remote)
{
    struct stack *s = (struct stack *)stack;

    (void)tp;
    (void)remote;
    s->error = errcode;
}

static msg_t *stack_alloc(tp_stack_t *stack, int flags, char const data[],
                          usize_t size, tport_t const *tp, tp_client_t *client)
{
    (void)stack;
    (void)data;
    (void)size;
    (void)tp;
    (void)client;
    return msg_create(sip_default_mclass(), flags);
}

static tport_stack_class_t const stack_class[1] = {{
    sizeof(tport_stack_class_t),
    stack_recv,
    stack_error,
    stack_alloc,
}};


/* tport passes the certificate path as both CAfile and CApath; a hashed copy
 * in the directory makes the CApath lookup work on every OpenSSL release. */
static int install_ca(char const *dir, char const *ca)
{
    char linkpath[256], target[512];
    FILE *f = fopen(ca, "r");
    X509 *x;
    unsigned long h;

    if (f == NULL)
        return -1;
    x = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (x == NULL)
        return -1;
    h = X509_subject_name_hash(x);
    X509_free(x);
    snprintf(linkpath, sizeof(linkpath), "%s/%08lx.0", dir, h);
    unlink(linkpath);
    snprintf(target, sizeof(target), "%s/cafile.pem", dir);
    return symlink(target, linkpath);
}

static int bind_tls(tport_t *master, char const *certdir, int server)
{
    tp_name_t name[1] = {{ "tls", "127.0.0.1", server ? "*" : "*", "*",
                           server ? "server" : "client", NULL }};
    char const *transports[] = { "tls", NULL };

    if (server)
        return tport_tbind(master, name, transports, TPTAG_SERVER(1),
                           TPTAG_CERTIFICATE(certdir), TPTAG_TLS_VERSION(0),
                           TAG_END());
    return tport_tbind(master, name, transports, TPTAG_SERVER(0),
                       TPTAG_CERTIFICATE(certdir), TPTAG_TLS_VERSION(0),
                       TPTAG_TLS_VERIFY_PEER(1), TAG_END());
}

static int run_session(char const *server_dir, char const *client_dir, char *got,
                       size_t gotlen)
{
    su_root_t *root;
    struct stack stack;
    tport_t *srv, *cli;
    tport_t *tp;
    su_addrinfo_t const *ai;
    char port[16];
    tp_name_t dst[1];
    msg_t *msg;
    sip_request_t *rq;
    sip_payload_t *pl;
    int i;

    memset(&stack, 0, sizeof(stack));
    got[0] = '\0';
    root = su_root_create(NULL);
    if (root == NULL)
        return -1;
    srv = tport_tcreate((tp_stack_t *)&stack, stack_class, root, TAG_END());
    cli = tport_tcreate((tp_stack_t *)&stack, stack_class, root, TAG_END());
    if (srv == NULL || cli == NULL)
        return -1;
    if (bind_tls(srv, server_dir, 1) < 0 || bind_tls(cli, client_dir, 0) < 0)
        return -1;
    tp = tport_primaries(srv);
    ai = tport_get_address(tp);
    if (ai == NULL || ai->ai_addr == NULL)
        return -1;
    snprintf(port, sizeof(port), "%u", ntohs(((struct sockaddr_in *)ai->ai_addr)->sin_port));

    msg = msg_create(sip_default_mclass(), 0);
    if (msg == NULL)
        return -1;
    rq = sip_request_make(msg_home(msg), "MESSAGE sip:server@127.0.0.1 SIP/2.0");
    if (rq == NULL || msg_header_insert(msg, msg_public(msg, NULL), (msg_header_t *)rq) < 0)
        return -1;
    pl = sip_payload_make(msg_home(msg), PAYLOAD);
    if (pl == NULL || msg_header_insert(msg, msg_public(msg, NULL), (msg_header_t *)pl) < 0)
        return -1;
    if (msg_serialize(msg, msg_public(msg, NULL)) < 0)
        return -1;

    memset(dst, 0, sizeof(dst));
    dst->tpn_proto = "tls";
    dst->tpn_canon = "127.0.0.1";
    dst->tpn_host = "127.0.0.1";
    dst->tpn_port = port;
    if (tport_tsend(tport_primaries(cli), msg, dst, TAG_END()) == NULL)
        return -1;

    for (i = 0; i < 100 && !stack.received; i++)
        su_root_step(root, 100);
    if (stack.received)
        snprintf(got, gotlen, "%s", stack.payload);
    return stack.received ? 0 : -1;
}

int main(int argc, char **argv)
{
    char const *cert = NULL, *key = NULL, *ca = NULL, *other_ca = NULL;
    char const *client_cert = NULL, *client_key = NULL;
    char srv_dir[] = "/tmp/sofia-l7-srv-XXXXXX";
    char cli_dir[] = "/tmp/sofia-l7-cli-XXXXXX";
    char bad_dir[] = "/tmp/sofia-l7-bad-XXXXXX";
    char path[256], cmd[512];
    char got[256], good_payload[256] = "";
    int i, good, bad;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("sofia-sip-l7-harness 1\n");
            return 0;
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key = argv[++i];
        } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            ca = argv[++i];
        } else if (strcmp(argv[i], "--other-ca") == 0 && i + 1 < argc) {
            other_ca = argv[++i];
        } else if (strcmp(argv[i], "--client-cert") == 0 && i + 1 < argc) {
            client_cert = argv[++i];
        } else if (strcmp(argv[i], "--client-key") == 0 && i + 1 < argc) {
            client_key = argv[++i];
        } else {
            fprintf(stderr, "usage: %s --cert FILE --key FILE --ca FILE --other-ca FILE\n",
                    argv[0]);
            return 3;
        }
    }
    if (client_cert == NULL)
        client_cert = cert;
    if (client_key == NULL)
        client_key = key;
    if (cert == NULL || key == NULL || ca == NULL || other_ca == NULL) {
        fprintf(stderr, "harness: --cert, --key, --ca and --other-ca are required\n");
        return 3;
    }
    if (mkdtemp(srv_dir) == NULL || mkdtemp(cli_dir) == NULL || mkdtemp(bad_dir) == NULL)
        return 1;
    snprintf(cmd, sizeof(cmd), "cat '%s' '%s' > '%s/agent.pem'; : > '%s/tls_seed.dat'; "
             "cp '%s' '%s/cafile.pem'", cert, key, srv_dir, srv_dir, ca, srv_dir);
    if (system(cmd) != 0)
        return 1;
    snprintf(cmd, sizeof(cmd), "cat '%s' '%s' > '%s/agent.pem'; : > '%s/tls_seed.dat'; "
             "cp '%s' '%s/cafile.pem'", client_cert, client_key, cli_dir, cli_dir, ca, cli_dir);
    if (system(cmd) != 0 || install_ca(cli_dir, ca) != 0)
        return 1;
    snprintf(cmd, sizeof(cmd), "cat '%s' '%s' > '%s/agent.pem'; : > '%s/tls_seed.dat'; "
             "cp '%s' '%s/cafile.pem'", client_cert, client_key, bad_dir, bad_dir, other_ca, bad_dir);
    if (system(cmd) != 0 || install_ca(bad_dir, other_ca) != 0)
        return 1;

    good = run_session(srv_dir, cli_dir, got, sizeof(got));
    if (good == 0)
        snprintf(good_payload, sizeof(good_payload), "%s", got);
    printf("tls_session=%s\n", good == 0 ? "ok" : "failed");
    printf("payload=%s\n", good == 0 ? got : "absent");
    bad = run_session(srv_dir, bad_dir, got, sizeof(got));
    printf("wrong_ca=%s\n", bad == 0 ? "accepted" : "rejected");
    (void)path;
    if (good == 0 && strcmp(good_payload, PAYLOAD) == 0 && bad != 0) {
        printf("result=ok\n");
        return 0;
    }
    printf("result=fail\n");
    return 1;
}
