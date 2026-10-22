/*
 * Phase-25 L7 workload for the `libssh` family.
 *
 * libssh's OpenSSL consumer path is its key/crypto backend (src/pki*.c and
 * src/ecdh*.c): RSA/EC key generation and import/export go through libcrypto.
 * This harness imports a pinned RSA private key, exports its public key blob,
 * and requires the exact wire-format blob; it then re-imports that blob and
 * compares the two keys. The negative controls use a corrupted copy of the
 * private key and a corrupted public blob, both of which must be rejected (or
 * must not equal the pinned blob).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <libssh/libssh.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char PRIVATE_B64[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA2GFJo1UNuCxGIuRhFg4S3pPWBg1BriiXTUl8ejbp7hag481N\n"
    "ue3k0S7SzqtNTX26v98nHfozyqVH2BE7XfZbcBBXdaGbMYivTD2C/XYkQO/WMU/M\n"
    "VgP76Z+1tWQUrSMn7BvA/spVMgWO4F4yJBKed0PkumrKBtPb5IYd/ps9S1MHH7Ht\n"
    "Db1w1BkMGao3FBk6fDAZg5gz3l/sF8qs8ut9fbOb7DI1i5YX1hymnNUSn5TQv7rI\n"
    "u0ffugUqOYEd+0xfNT6ObhUeSkTOVsBzEIeKztbjOgiXCDMZohfowOBx8qmFHhql\n"
    "5AdFy251yUl1ZXzASr6LVy5TJ3NCts+/W7AbRwIDAQABAoIBAA1oBbR5dhalo5jQ\n"
    "1pUTvSaOOVH5q0qbmDhBJ9W4pkjKnSBQHZM6ApXVVVlZsrns4s+1h0prsJ7LG8bu\n"
    "1mNNer/YO1r97swkYFwUaZPDqJ5fXcGDZLEloQuKCiuZblCF35jY5V3D8oBdaMtM\n"
    "+sVSZAAWtEq6iBbhNHwVtTELtEIA30NAyq+E3SJgZek0OMVPqFDaW+c1gfoHdTej\n"
    "4ELgE/G5mvd7xfkCYR67XdLFEVgUsj4dU0QTgvYUU231AfPQCZrfgWH2WLisu42l\n"
    "82CVaPbnlJxq6yE7DXRkUsabSbfBU0TFtKpzrBl+/ngaELga0Bogx9QYa/BZR+04\n"
    "L1BYRAUCgYEA7Q8q1lzw3NWIqVPWD0tcFnotwAKPOICbKTrieZgi8FFxBWzFRlYe\n"
    "hxnXBfgYFxf3w58dzusZQ/9f1zkEfw1Y6NNfz9rp4C6s6bq3/JMRhfxhraUq6luV\n"
    "NRn5IbdHIUhlZkaKPVb3wgUZzZPNz9IOfAVefdCYD+V9DUn14niUw+sCgYEA6asl\n"
    "RqY8WYkDDJT1mmaEW/4OyP9Sm8EKELADGJtqh3K2G72jICWGj/C6OnfbJKBrceMz\n"
    "of7p2pSkaNRjyUbIuN7SNq4re7PqmHT5vWpG22mLt0SjMipqFqAnqA36AgMQc9KN\n"
    "s4jo5UPx3ZJZI+DxvKlv8XpXFoprdSpEWJ0m2xUCgYBLmku6I9f5ReyYvBEHvav3\n"
    "yy1uECLnDTTu2EXEK73w0Lhv13mu7eY8hgQqdi4Qp2cwLz3NcPMU2YwSUq/ZaUNS\n"
    "tZ7X5mQySBCDVjY5ShoLlir8uzFNnrmePtNSamY3+iPEk3ihCWxop0HMa3f28HII\n"
    "IZo6G91zLGhOZakSegxP0wKBgHlCwbNqLUNhoN10qAgaT3HV5CJWra36fZivXsv0\n"
    "S1JDK1I2FWNnVe94w4v4Cxd00I1nlLHqsb0nCjMElUwsmZmmuHx74kDt2z6G5dtw\n"
    "PZk7qq/OxMoRzMA1GJ9TsXw9ztnsWHDlCceAfRG5Et1VrN11KIyuKmeeKanB53n9\n"
    "A98JAoGBAOtcoU2isbe4sa6F7tLhuGbBWejaM26xTMU2+3umZQdIc60g7HFSjH6W\n"
    "c1MgZkoPs3ANqpxrufcBdvJZ3DL03i+CO5FhRelTKdeiwf/KS7yaRlkb5YuOscmV\n"
    "Lj/CLhwbpVGjJWbpguF9w4z0IYo/jKh4jv9ZrQ/i2/WL+mChtcYk\n"
    "-----END RSA PRIVATE KEY-----\n";

/* Filled from the pinned key below by the first measurement run; the harness
 * refuses to report success until the exported blob matches it exactly. */
static const char EXPECTED_PUBKEY[] =
    "AAAAB3NzaC1yc2EAAAADAQABAAABAQDYYUmjVQ24LEYi5GEWDhLek9YGDUGuKJdNSXx6NunuFqDjzU257eTRLtLOq01Nfbq/"
    "3ycd+jPKpUfYETtd9ltwEFd1oZsxiK9MPYL9diRA79YxT8xWA/vpn7W1ZBStIyfsG8D+ylUyBY7gXjIkEp53Q+S6asoG09vk"
    "hh3+mz1LUwcfse0NvXDUGQwZqjcUGTp8MBmDmDPeX+wXyqzy6319s5vsMjWLlhfWHKac1RKflNC/usi7R9+6BSo5gR37TF81"
    "Po5uFR5KRM5WwHMQh4rO1uM6CJcIMxmiF+jA4HHyqYUeGqXkB0XLbnXJSXVlfMBKvotXLlMnc0K2z79bsBtH";

static char *export_blob(ssh_key key)
{
    char *blob = NULL;

    if (ssh_pki_export_pubkey_base64(key, &blob) != SSH_OK)
        return NULL;
    return blob;
}

int main(int argc, char **argv)
{
    ssh_key key = NULL, roundtrip = NULL, tampered = NULL;
    char *blob = NULL, *round_blob = NULL;
    char corrupt[sizeof(PRIVATE_B64)];
    int import_ok, blob_ok = 0, round_ok = 0, private_tamper_ok, public_tamper_ok;

    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("libssh-l7-harness 1\n");
        return 0;
    }

    if (ssh_init() != SSH_OK) {
        fprintf(stderr, "ssh_init failed\n");
        return 1;
    }

    import_ok = (ssh_pki_import_privkey_base64(PRIVATE_B64, NULL, NULL, NULL, &key) == SSH_OK
                 && key != NULL);
    printf("key_import=%s\n", import_ok ? "ok" : "failed");

    if (import_ok) {
        blob = export_blob(key);
        blob_ok = (blob != NULL && strcmp(blob, EXPECTED_PUBKEY) == 0);
        printf("pubkey_blob=%s\n", blob_ok ? "ok" : "mismatch");

        if (blob != NULL
            && ssh_pki_import_pubkey_base64(blob, SSH_KEYTYPE_RSA, &roundtrip) == SSH_OK
            && roundtrip != NULL) {
            round_blob = export_blob(roundtrip);
            round_ok = (round_blob != NULL && strcmp(round_blob, EXPECTED_PUBKEY) == 0
                        && ssh_key_cmp(key, roundtrip, SSH_KEY_CMP_PUBLIC) == 0);
        }
        printf("roundtrip=%s\n", round_ok ? "ok" : "failed");
    } else {
        blob_ok = round_ok = 0;
    }

    /* Negative control 1: a corrupted private-key encoding must not import as
     * the pinned key (an import error is the expected outcome). */
    memcpy(corrupt, PRIVATE_B64, sizeof(PRIVATE_B64));
    if (strlen(corrupt) > 120)
        corrupt[120] = (corrupt[120] == 'A') ? 'B' : 'A';
    private_tamper_ok = 1;
    if (ssh_pki_import_privkey_base64(corrupt, NULL, NULL, NULL, &tampered) == SSH_OK
        && tampered != NULL) {
        char *bad_blob = export_blob(tampered);
        private_tamper_ok = (bad_blob == NULL || strcmp(bad_blob, EXPECTED_PUBKEY) != 0);
        free(bad_blob);
        ssh_key_free(tampered);
    }
    printf("tamper=%s\n", private_tamper_ok ? "rejected" : "accepted");

    /* Negative control 2: a corrupted public blob must not re-import as the
     * pinned key. */
    public_tamper_ok = 1;
    if (blob != NULL) {
        char badpub[4096];
        ssh_key badkey = NULL;

        snprintf(badpub, sizeof(badpub), "%s", blob);
        if (strlen(badpub) > 60)
            badpub[60] = (badpub[60] == 'A') ? 'B' : 'A';
        if (ssh_pki_import_pubkey_base64(badpub, SSH_KEYTYPE_RSA, &badkey) == SSH_OK
            && badkey != NULL) {
            char *bad_blob = export_blob(badkey);
            public_tamper_ok = (bad_blob == NULL
                                || strcmp(bad_blob, EXPECTED_PUBKEY) != 0);
            free(bad_blob);
            ssh_key_free(badkey);
        }
    }
    printf("public_tamper=%s\n", public_tamper_ok ? "rejected" : "accepted");

    free(blob);
    free(round_blob);
    if (key != NULL)
        ssh_key_free(key);
    if (roundtrip != NULL)
        ssh_key_free(roundtrip);

    ssh_finalize();

    if (import_ok && blob_ok && round_ok && private_tamper_ok && public_tamper_ok) {
        printf("result=ok\n");
        return 0;
    }
    printf("result=fail\n");
    return 1;
}
