/*
 * openssl-rs — admitted workload for libpaho-mqtt (paho.mqtt.c).
 *
 * paho.mqtt.c ships no executable.  This harness is a test-only consumer of the
 * rebuilt library: it creates an MQTT client with the TLS transport, trusts the
 * fixture CA, connects to a local peer and requires the peer's CONNACK.  The
 * workload runs it once with the real CA and once with an unrelated CA; only
 * the first may reach CONNACK.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "MQTTClient.h"

int
main(int argc, char **argv)
{
    MQTTClient client;
    MQTTClient_connectOptions opts = MQTTClient_connectOptions_initializer;
    MQTTClient_SSLOptions ssl = MQTTClient_SSLOptions_initializer;
    char uri[64];
    int rc;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("paho-mqtt-l7-harness\n");
        return 0;
    }
    if (argc < 3) {
        fprintf(stderr, "usage: %s --version | <ca-file> <port>\n", argv[0]);
        return 2;
    }

    snprintf(uri, sizeof(uri), "ssl://127.0.0.1:%d", atoi(argv[2]));
    rc = MQTTClient_create(&client, uri, "l7-harness",
                           MQTTCLIENT_PERSISTENCE_NONE, NULL);
    if (rc != MQTTCLIENT_SUCCESS) {
        printf("create=fail rc=%d\n", rc);
        return 1;
    }

    ssl.trustStore = argv[1];
    ssl.enableServerCertAuth = 1;
    opts.ssl = &ssl;
    opts.keepAliveInterval = 10;
    opts.cleansession = 1;
    opts.connectTimeout = 8;

    rc = MQTTClient_connect(client, &opts);
    printf("connect=%s rc=%d\n", rc == MQTTCLIENT_SUCCESS ? "ok" : "fail", rc);
    if (rc == MQTTCLIENT_SUCCESS)
        MQTTClient_disconnect(client, 1000);
    MQTTClient_destroy(&client);
    return rc == MQTTCLIENT_SUCCESS ? 0 : 1;
}
