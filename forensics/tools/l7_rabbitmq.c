/*
 * openssl-rs — admitted workload for rabbitmq-c.
 *
 * rabbitmq-c ships no executable.  This harness is a test-only consumer of the
 * rebuilt library: it creates an SSL socket with the fixture CA, verifies the
 * peer, and opens the TLS connection to a local peer.  The workload runs it
 * once with the real CA and once with an unrelated CA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rabbitmq-c/amqp.h>
#include <rabbitmq-c/ssl_socket.h>

int
main(int argc, char **argv)
{
    amqp_connection_state_t conn;
    amqp_socket_t *socket;
    int rc;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("rabbitmq-c-l7-harness\n");
        return 0;
    }
    if (argc < 3) {
        fprintf(stderr, "usage: %s --version | <ca-file> <port>\n", argv[0]);
        return 2;
    }

    conn = amqp_new_connection();
    if (conn == NULL) {
        printf("new=fail\n");
        return 1;
    }
    socket = amqp_ssl_socket_new(conn);
    if (socket == NULL) {
        printf("socket=fail\n");
        amqp_destroy_connection(conn);
        return 1;
    }
    amqp_ssl_socket_set_cacert(socket, argv[1]);
    amqp_ssl_socket_set_verify_peer(socket, 1);
    amqp_ssl_socket_set_verify_hostname(socket, 1);

    rc = amqp_socket_open(socket, "localhost", atoi(argv[2]));
    printf("open=%s rc=%d\n", rc == AMQP_STATUS_OK ? "ok" : "fail", rc);
    amqp_destroy_connection(conn);
    return rc == AMQP_STATUS_OK ? 0 : 1;
}
