/*
 * l7_iperf3.c — the admitted L7 workload observable for the iperf3 family.
 *
 * iperf3 3.17.1 uses OpenSSL for its RSA authenticated mode: the client encrypts
 * `{username}password` for the server, and the server checks the SHA-256 digest of the salted
 * password against its authorized-users file (src/iperf_auth.c). The RSA transport cannot complete
 * on this venue: `encrypt_rsa_message()` passes an output length of 0 to `EVP_PKEY_encrypt()`, so
 * every OpenSSL 3 build answers "Provider routines::output buffer too small" and the client's token
 * is empty. That failure is identical against the authority and the candidate, so it is not a
 * conversion divergence; the CLI auth path is therefore not the asserted observable.
 *
 * This harness drives the part of the same libiperf code that does work on both subjects: the
 * SHA-256 digest of a salted credential (`sha256()`) and the authorized-users decision
 * (`check_authentication()`), including the wrong-password and stale-timestamp rejections. It links
 * the family's own rebuilt libiperf, which links the subject's libcrypto.
 *
 * It is a test-only consumer: it is never part of the iperf3 build or any release artefact.
 */
#include <stdio.h>
#include <time.h>

/* libiperf's exported entry points (src/iperf_auth.h); declared here so the harness needs no
 * build-tree headers. */
void sha256(const char *string, char outputBuffer[65]);
int check_authentication(const char *username, const char *password, const time_t ts,
                         const char *filename, int skew_threshold);

int main(int argc, char **argv)
{
    char hex[65];
    time_t now;

    if (argc != 2) {
        fprintf(stderr, "usage: %s AUTHORIZED_USERS_FILE\n", argv[0]);
        return 2;
    }

    sha256("{l7}secret", hex);
    printf("sha256=%s\n", hex);

    now = time(NULL);
    printf("auth_ok=%s\n",
           check_authentication("l7", "secret", now, argv[1], 300) == 0 ? "accepted" : "rejected");
    printf("auth_wrong=%s\n",
           check_authentication("l7", "wrong", now, argv[1], 300) == 3 ? "rejected" : "accepted");
    printf("auth_stale=%s\n",
           check_authentication("l7", "secret", now - 3600, argv[1], 300) == 1 ? "rejected"
                                                                              : "accepted");
    return 0;
}
