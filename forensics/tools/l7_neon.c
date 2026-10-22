/* libneon HTTPS client harness: verify a fetched body against the fixture CA. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ne_session.h>
#include <ne_request.h>
#include <ne_ssl.h>
#include <ne_socket.h>

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--version") == 0) { printf("neon-l7-harness\n"); return 0; }
    if (argc < 4) { printf("neon-l7-harness usage: ca port path\n"); return 2; }
    const char *ca = argv[1];
    unsigned port = (unsigned) strtoul(argv[2], NULL, 10);
    const char *path = argv[3];
    ne_sock_init();
    ne_session *sess = ne_session_create("https", "127.0.0.1", port);
    ne_ssl_certificate *cert = ne_ssl_cert_read(ca);
    if (cert == NULL) { printf("ca=read-failed\n"); return 3; }
    ne_ssl_trust_cert(sess, cert);
    ne_ssl_cert_free(cert);
    ne_set_connect_timeout(sess, 10);
    ne_request *req = ne_request_create(sess, "GET", path);
    int rc = ne_begin_request(req);
    if (rc != NE_OK) {
        printf("connect=failed status=0 body=\n");
        ne_request_destroy(req);
        ne_session_destroy(sess);
        ne_sock_exit();
        return 0;
    }
    const ne_status *st = ne_get_status(req);
    char body[2048]; size_t n = 0; ssize_t r;
    while ((r = ne_read_response_block(req, body + n, sizeof(body) - 1 - n)) > 0) {
        n += (size_t) r;
        if (n >= sizeof(body) - 1) break;
    }
    body[n] = 0;
    ne_end_request(req);
    for (size_t i = 0; i < n; i++) if (body[i] == 0x0a || body[i] == 0x0d) body[i] = 0x20;
    printf("status=%d body=%s\n", st ? st->code : 0, body);
    ne_request_destroy(req);
    ne_session_destroy(sess);
    ne_sock_exit();
    return 0;
}
