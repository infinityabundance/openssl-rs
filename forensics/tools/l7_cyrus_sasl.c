/*
 * Phase-25 L7 workload for the library-only `cyrus-sasl` family.
 *
 * cyrus-sasl ships no executable of its own. This harness drives the
 * library's own client and server SASL APIs over a socketpair, authenticating
 * with DIGEST-MD5 -- a mechanism whose response is computed through
 * libcrypto (MD5/HMAC), so the workload exercises the family's OpenSSL
 * consumer path rather than a banner. The server resolves the user secret
 * through an in-process auxprop plugin (no on-disk sasldb backend is built by
 * this venue). A second session with a wrong password must be rejected.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include <sasl.h>
#include <saslplug.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define FIXTURE_USER "fixture-user"
#define FIXTURE_PASS "phase25-correct-password"
#define FIXTURE_REALM "fixture.realm"
#define MECH "DIGEST-MD5"

struct fixture {
    const char *user;
    const char *pass;
};

/* ------------------------------------------------------------------ auxprop */

static struct fixture g_fixture = {FIXTURE_USER, FIXTURE_PASS};

static int aux_lookup(void *ctx, sasl_server_params_t *sparams, unsigned flags,
                      const char *user, unsigned ulen)
{
    const struct fixture *f = ctx;
    unsigned n = 0;

    if (!sparams || !user || !sparams->propctx) return SASL_BADPARAM;
    (void)flags;

    /* the server passes the canonical "user@realm"; the fixture user is the local part */
    while (n < ulen && user[n] != '@') n++;
    if (n != strlen(f->user) || memcmp(user, f->user, n) != 0)
        return SASL_NOUSER;

    if (sparams->utils->prop_set(sparams->propctx, SASL_AUX_PASSWORD,
                                 f->pass, (unsigned)strlen(f->pass)) != SASL_OK)
        return SASL_NOUSER;
    return SASL_OK;
}

static sasl_auxprop_plug_t aux_plug = {
    0, 0, &g_fixture, NULL, aux_lookup, "fixture", NULL,
};

static int aux_init(const sasl_utils_t *utils, int max_version, int *out_version,
                    sasl_auxprop_plug_t **plug, const char *plugname)
{
    (void)utils;
    (void)plugname;
    if (!out_version || !plug) return SASL_BADPARAM;
    if (max_version < SASL_AUXPROP_PLUG_VERSION) return SASL_BADVERS;
    *out_version = SASL_AUXPROP_PLUG_VERSION;
    *plug = &aux_plug;
    return SASL_OK;
}

/* ---------------------------------------------------------------- callbacks */

static int cb_user(void *ctx, int id, const char **result, unsigned *len)
{
    (void)id;
    *result = ctx;
    if (len) *len = (unsigned)strlen(ctx);
    return SASL_OK;
}

static int cb_pass(sasl_conn_t *conn, void *ctx, int id, sasl_secret_t **psecret)
{
    const char *pass = ctx;
    size_t len = strlen(pass);
    static sasl_secret_t *secret;

    (void)conn;
    (void)id;
    if (!psecret) return SASL_BADPARAM;
    free(secret);
    secret = malloc(sizeof(*secret) + len);
    if (!secret) return SASL_NOMEM;
    secret->len = (unsigned)len;
    memcpy(secret->data, pass, len);
    *psecret = secret;
    return SASL_OK;
}

static int cb_log(void *ctx, int level, const char *message)
{
    (void)ctx;
    if (level <= SASL_LOG_NOTE)
        fprintf(stderr, "sasl[%d]: %s\n", level, message);
    return SASL_OK;
}

static int cb_getopt(void *ctx, const char *plugin_name, const char *option,
                     const char **result, unsigned *len)
{
    (void)ctx;
    (void)plugin_name;
    (void)option;
    (void)result;
    (void)len;
    return SASL_FAIL;
}

static int cb_canon_user(sasl_conn_t *conn, void *ctx, const char *in,
                         unsigned inlen, unsigned flags, const char *user_realm,
                         char *out, unsigned out_max, unsigned *out_len)
{
    unsigned n = inlen < out_max - 1 ? inlen : out_max - 1;

    (void)conn;
    (void)ctx;
    (void)flags;
    (void)user_realm;
    memcpy(out, in, n);
    out[n] = '\0';
    if (out_len) *out_len = n;
    return SASL_OK;
}

static int cb_checkpass(sasl_conn_t *conn, void *ctx, const char *user,
                        const char *pass, unsigned passlen)
{
    const struct fixture *f = ctx;
    (void)conn;
    if (strcmp(user, f->user) != 0) return SASL_NOUSER;
    if (strlen(f->pass) != passlen || memcmp(f->pass, pass, passlen) != 0)
        return SASL_FAIL;
    return SASL_OK;
}

/* ------------------------------------------------------------- socket relay */

static int send_all(int fd, const char *buf, unsigned len)
{
    uint32_t n = htonl(len);

    if (write(fd, &n, sizeof(n)) != (ssize_t)sizeof(n)) return -1;
    if (len && write(fd, buf, len) != (ssize_t)len) return -1;
    return 0;
}

static int recv_all(int fd, char **buf, unsigned *len)
{
    uint32_t n;
    ssize_t got;
    char *out;

    if (read(fd, &n, sizeof(n)) != (ssize_t)sizeof(n)) return -1;
    n = ntohl(n);
    if (n > 65536) return -1;
    out = malloc(n ? n : 1);
    if (!out) return -1;
    for (unsigned done = 0; done < n;) {
        got = read(fd, out + done, n - done);
        if (got <= 0) {
            free(out);
            return -1;
        }
        done += (unsigned)got;
    }
    *buf = out;
    *len = n;
    return 0;
}

/* ------------------------------------------------------------------ session */

struct result {
    int client_ok;
    int server_ok;
};

static int exchange(sasl_conn_t *client, sasl_conn_t *server, int cfd, int sfd,
                    struct result *out)
{
    const char *mech = NULL;
    const char *cout = NULL, *sout = NULL;
    unsigned coutlen = 0, soutlen = 0;
    int rc_c, rc_s;

    rc_c = sasl_client_start(client, MECH, NULL, &cout, &coutlen, &mech);
    if (rc_c != SASL_OK && rc_c != SASL_CONTINUE) return -1;
    if (send_all(cfd, cout, coutlen) != 0) return -1;

    {
        char *in = NULL;
        unsigned inlen = 0;
        if (recv_all(sfd, &in, &inlen) != 0) return -1;
        rc_s = sasl_server_start(server, mech ? mech : MECH, in, inlen, &sout, &soutlen);
        free(in);
    }
    if (rc_s != SASL_OK && rc_s != SASL_CONTINUE) return -1;
    if (send_all(sfd, sout, soutlen) != 0) return -1;

    while (rc_c == SASL_CONTINUE) {
        char *in = NULL;
        unsigned inlen = 0;

        if (recv_all(cfd, &in, &inlen) != 0) return -1;
        rc_c = sasl_client_step(client, in, inlen, NULL, &cout, &coutlen);
        free(in);
        if (rc_c != SASL_OK && rc_c != SASL_CONTINUE) break;
        if (send_all(cfd, cout, coutlen) != 0) return -1;

        if (rc_s == SASL_CONTINUE) {
            in = NULL;
            inlen = 0;
            if (recv_all(sfd, &in, &inlen) != 0) return -1;
            rc_s = sasl_server_step(server, in, inlen, &sout, &soutlen);
            free(in);
            if (rc_s != SASL_OK && rc_s != SASL_CONTINUE) break;
            if (send_all(sfd, sout, soutlen) != 0) return -1;
        }
    }

    out->client_ok = (rc_c == SASL_OK);
    out->server_ok = (rc_s == SASL_OK);
    if (!out->client_ok)
        fprintf(stderr, "client: rc=%d detail=%s\n", rc_c,
                sasl_errdetail(client) ? sasl_errdetail(client) : "(none)");
    if (!out->server_ok)
        fprintf(stderr, "server: rc=%d detail=%s\n", rc_s,
                sasl_errdetail(server) ? sasl_errdetail(server) : "(none)");
    return 0;
}

static int run_session(const char *client_pass, struct result *out)
{
    struct fixture fix = {FIXTURE_USER, FIXTURE_PASS};
    sasl_callback_t client_cb[] = {
        {SASL_CB_USER, (int (*)(void))cb_user, (void *)FIXTURE_USER},
        {SASL_CB_AUTHNAME, (int (*)(void))cb_user, (void *)FIXTURE_USER},
        {SASL_CB_PASS, (int (*)(void))cb_pass, (void *)client_pass},
        {SASL_CB_LOG, (int (*)(void))cb_log, NULL},
        {SASL_CB_GETOPT, (int (*)(void))cb_getopt, NULL},
        {SASL_CB_CANON_USER, (int (*)(void))cb_canon_user, NULL},
        {SASL_CB_LIST_END, NULL, NULL},
    };
    sasl_callback_t server_cb[] = {
        {SASL_CB_LOG, (int (*)(void))cb_log, NULL},
        {SASL_CB_GETOPT, (int (*)(void))cb_getopt, NULL},
        {SASL_CB_SERVER_USERDB_CHECKPASS, (int (*)(void))cb_checkpass, &fix},
        {SASL_CB_CANON_USER, (int (*)(void))cb_canon_user, NULL},
        {SASL_CB_LIST_END, NULL, NULL},
    };
    sasl_conn_t *client = NULL, *server = NULL;
    int pair[2] = {-1, -1};
    struct timeval tv = {5, 0};
    int rc = 1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return 1;
    setsockopt(pair[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(pair[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (sasl_client_new("smtp", "localhost", NULL, NULL, client_cb, 0, &client)
        != SASL_OK)
        goto done;
    if (sasl_server_new("smtp", "localhost", FIXTURE_REALM, NULL, NULL,
                        server_cb, 0, &server) != SASL_OK)
        goto done;
    if (exchange(client, server, pair[0], pair[1], out) == 0)
        rc = 0;

 done:
    if (client) sasl_dispose(&client);
    if (server) sasl_dispose(&server);
    close(pair[0]);
    close(pair[1]);
    return rc;
}

int main(int argc, char **argv)
{
    struct result good, bad;

    (void)argv;
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("cyrus-sasl-l7-harness %s\n", MECH);
        return 0;
    }

    if (sasl_client_init(NULL) != SASL_OK || sasl_server_init(NULL, "l7-fixture") != SASL_OK) {
        printf("init=failed\n");
        return 1;
    }
    if (sasl_auxprop_add_plugin("fixture", aux_init) != SASL_OK) {
        printf("auxprop=failed\n");
        return 1;
    }

    memset(&good, 0, sizeof(good));
    memset(&bad, 0, sizeof(bad));
    if (run_session(FIXTURE_PASS, &good) != 0) {
        printf("session=error\n");
        return 1;
    }
    if (run_session("phase25-wrong-password", &bad) != 0) {
        printf("negative-session=error\n");
        return 1;
    }

    printf("mech=%s\n", MECH);
    printf("auth=%s\n", (good.client_ok && good.server_ok) ? "ok" : "failed");
    printf("wrong-password=%s\n",
           (bad.client_ok || bad.server_ok) ? "accepted" : "rejected");
    return (good.client_ok && good.server_ok && !bad.client_ok && !bad.server_ok) ? 0 : 1;
}
