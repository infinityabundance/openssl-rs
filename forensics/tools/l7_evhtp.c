/* libevhtp TLS server harness: serve one fixed payload over a verified TLS connection. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <evhtp/evhtp.h>
#include <event2/event.h>

static const char *body_text = "phase25-l7-libevhtp";

static void handler(evhtp_request_t *req, void *arg) {
    struct event_base *base = (struct event_base *) arg;
    evbuffer_add(req->buffer_out, body_text, strlen(body_text));
    evbuffer_add(req->buffer_out, "\n", 1);
    evhtp_request_set_keepalive(req, 0);
    evhtp_send_reply(req, EVHTP_RES_OK);
    struct timeval tv = {0, 500000};
    event_base_loopexit(base, &tv);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("libevhtp-l7-harness\n");
        return 0;
    }
    if (argc < 4) { printf("libevhtp-l7-harness usage: port cert key\n"); return 2; }
    unsigned short port = (unsigned short) strtoul(argv[1], NULL, 10);
    struct event_base *base = event_base_new();
    if (!base) { printf("server=base-failed\n"); return 3; }
    evhtp_t *htp = evhtp_new(base, NULL);
    if (!htp) { printf("server=htp-failed\n"); return 3; }
    evhtp_set_cb(htp, "/payload.txt", handler, base);
    evhtp_ssl_cfg_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.pemfile = argv[2];
    scfg.privfile = argv[3];
    scfg.ssl_opts = 0;
    if (evhtp_ssl_init(htp, &scfg) != 0) { printf("server=ssl-failed\n"); return 3; }
    if (evhtp_bind_socket(htp, "127.0.0.1", port, 1024) != 0) { printf("server=bind-failed\n"); return 3; }
    printf("READY %u\n", (unsigned) port);
    fflush(stdout);
    event_base_dispatch(base);
    evhtp_free(htp);
    event_base_free(base);
    return 0;
}
