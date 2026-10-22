/*
 * openssl-rs — admitted workload for libsrtp.
 *
 * libsrtp ships no executable.  This harness is a test-only consumer of the
 * rebuilt library with its OpenSSL crypto backend: it protects an RTP packet
 * under a known key, unprotects it, and requires a session with a different key
 * to reject the protected packet.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <srtp.h>

static const unsigned char key_a[30] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
};
static const unsigned char key_b[30] = {
    0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
    0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
    0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
    0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe,
};

static int
make_session(srtp_t *session, const unsigned char *key, unsigned long ssrc)
{
    srtp_policy_t policy;

    memset(&policy, 0, sizeof(policy));
    srtp_crypto_policy_set_rtp_default(&policy.rtp);
    srtp_crypto_policy_set_rtcp_default(&policy.rtcp);
    policy.ssrc.type = ssrc_specific;
    policy.ssrc.value = (uint32_t) ssrc;
    policy.key = (unsigned char *) key;
    policy.next = NULL;
    return srtp_create(session, &policy);
}

int
main(int argc, char **argv)
{
    srtp_t sender, receiver, wrong;
    unsigned char packet[256];
    unsigned char plain[256];
    unsigned char saved[256];
    int len = 12 + 16, protected_len, rc;
    const char *payload = "template-payload";
    int i;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("libsrtp-l7-harness\n");
        return 0;
    }

    if (srtp_init() != srtp_err_status_ok) {
        printf("init=fail\n");
        return 1;
    }
    memset(packet, 0, sizeof(packet));
    packet[0] = 0x80;
    packet[1] = 96;
    packet[2] = 0x00;
    packet[3] = 0x01;
    packet[4] = 0x00;
    packet[5] = 0x00;
    packet[6] = 0x00;
    packet[7] = 0x02;
    packet[8] = 0xde;
    packet[9] = 0xad;
    packet[10] = 0xbe;
    packet[11] = 0xef;
    for (i = 0; payload[i] != '\0' && i < 16; i++)
        packet[12 + i] = (unsigned char) payload[i];
    memcpy(saved, packet, (size_t) len);

    if (make_session(&sender, key_a, 0xdeadbeefUL) != srtp_err_status_ok ||
        make_session(&receiver, key_a, 0xdeadbeefUL) != srtp_err_status_ok ||
        make_session(&wrong, key_b, 0xdeadbeefUL) != srtp_err_status_ok) {
        printf("session=fail\n");
        return 1;
    }

    protected_len = len;
    rc = srtp_protect(sender, packet, &protected_len);
    printf("protect=%s rc=%d\n", rc == srtp_err_status_ok ? "ok" : "fail", rc);
    if (rc != srtp_err_status_ok)
        return 1;

    memcpy(plain, packet, (size_t) protected_len);
    rc = srtp_unprotect(receiver, plain, &protected_len);
    printf("unprotect=%s rc=%d\n", rc == srtp_err_status_ok ? "ok" : "fail", rc);
    if (rc != srtp_err_status_ok || memcmp(plain, saved, (size_t) len) != 0)
        return 1;

    memcpy(plain, packet, (size_t) protected_len);
    protected_len = len;
    rc = srtp_unprotect(wrong, plain, &protected_len);
    printf("wrong-key=%s rc=%d\n", rc == srtp_err_status_auth_fail ? "rejected" : "accepted",
           rc);

    srtp_dealloc(sender);
    srtp_dealloc(receiver);
    srtp_dealloc(wrong);
    srtp_shutdown();
    return rc == srtp_err_status_auth_fail ? 0 : 1;
}
