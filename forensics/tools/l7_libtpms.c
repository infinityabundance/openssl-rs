/*
 * Phase-25 L7 workload for the `libtpms` family.
 *
 * libtpms' OpenSSL consumer path is its TPM2 crypto/RNG implementation, reached through the
 * TPMLIB command interface (TPMLIB_Process). This harness starts a TPM2 instance, asks for the
 * fixed properties (family indicator "2.0" and manufacturer "IBM"), requests 32 random bytes, and
 * sends an unknown command code as the negative control. The response codes and payloads are
 * concrete: the fixed-property values come from libtpms' own tables and the random buffer comes
 * from the subject libcrypto's RNG.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t rd32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int send_cmd(const char *label, const unsigned char *cmd, uint32_t cmdlen,
                    unsigned char **resp, uint32_t *resplen, uint32_t *rc)
{
    uint32_t size = 0;
    TPM_RESULT rv;

    *resp = NULL;
    *resplen = 0;
    rv = TPMLIB_Process(resp, resplen, &size, (unsigned char *)cmd, cmdlen);
    if (rv != TPM_SUCCESS) {
        printf("%s_process=failed rv=%u\n", label, (unsigned)rv);
        return -1;
    }
    if (*resp == NULL || *resplen < 10) {
        printf("%s_response=truncated\n", label);
        return -1;
    }
    *rc = rd32(*resp + 6);
    return 0;
}

int main(int argc, char **argv)
{
    unsigned char startup[12] = { 0x80, 0x01, 0, 0, 0, 12,
                                  0, 0, 0x01, 0x44, 0, 0 };
    unsigned char getcap[22] = { 0x80, 0x01, 0, 0, 0, 22,
                                 0, 0, 0x01, 0x7a, 0, 0, 0, 6,
                                 0, 0, 0x01, 0, 0, 0, 0, 6 };
    unsigned char getrandom[12] = { 0x80, 0x01, 0, 0, 0, 12,
                                    0, 0, 0x01, 0x7b, 0, 32 };
    unsigned char unknown[10] = { 0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0xff };
    unsigned char *resp = NULL;
    uint32_t resplen = 0, rc = 0;
    int ok = 1, have_family = 0, have_manufacturer = 0, i, n;
    TPM_RESULT rv;

    (void)argc;
    (void)argv;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("libtpms-l7-harness 1\n");
        return 0;
    }

    rv = TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
    if (rv != TPM_SUCCESS) {
        printf("tpm2_startup=failed choose=%u\n", (unsigned)rv);
        return 1;
    }
    rv = TPMLIB_MainInit();
    printf("tpm2_startup=%s\n", rv == TPM_SUCCESS ? "ok" : "failed");
    if (rv != TPM_SUCCESS)
        return 1;

    if (send_cmd("startup", startup, sizeof(startup), &resp, &resplen, &rc) != 0 ||
        rc != 0) {
        printf("startup_rc=0x%08x\n", (unsigned)rc);
        ok = 0;
    }
    free(resp);
    resp = NULL;

    if (send_cmd("getcap", getcap, sizeof(getcap), &resp, &resplen, &rc) != 0) {
        ok = 0;
    } else if (rc != 0 || resplen < 19 || rd32(resp + 11) != 6) {
        printf("getcap_rc=0x%08x len=%u\n", (unsigned)rc, (unsigned)resplen);
        ok = 0;
    } else {
        n = (int)rd32(resp + 15);
        for (i = 0; i < n && 19 + 8 * (i + 1) <= (int)resplen; i++) {
            uint32_t prop = rd32(resp + 19 + 8 * i);
            uint32_t value = rd32(resp + 23 + 8 * i);

            if (prop == 0x00000100u) {
                printf("family=%c%c%c\n", (char)(value >> 24), (char)(value >> 16),
                       (char)(value >> 8));
                have_family = (value == 0x322e3000u);
            } else if (prop == 0x00000105u) {
                printf("manufacturer=%c%c%c\n", (char)(value >> 24), (char)(value >> 16),
                       (char)(value >> 8));
                have_manufacturer = (value == 0x49424d00u);
            }
        }
        if (!have_family || !have_manufacturer)
            ok = 0;
    }
    free(resp);
    resp = NULL;

    if (send_cmd("getrandom", getrandom, sizeof(getrandom), &resp, &resplen, &rc) != 0 ||
        rc != 0 || resplen != 44 || ((uint32_t)resp[10] << 8 | resp[11]) != 32) {
        printf("getrandom_rc=0x%08x len=%u\n", (unsigned)rc, (unsigned)resplen);
        ok = 0;
    } else {
        printf("random=32\n");
    }
    free(resp);
    resp = NULL;

    /* Negative control: an unknown command code must be refused, not accepted or crashed. */
    if (send_cmd("unknown", unknown, sizeof(unknown), &resp, &resplen, &rc) != 0 ||
        rc == 0) {
        printf("unknown_cc=accepted rc=0x%08x\n", (unsigned)rc);
        ok = 0;
    } else {
        printf("unknown_cc=rejected rc=0x%08x\n", (unsigned)rc);
    }
    free(resp);

    TPMLIB_Terminate();
    printf("result=%s\n", ok ? "ok" : "fail");
    return ok ? 0 : 1;
}
