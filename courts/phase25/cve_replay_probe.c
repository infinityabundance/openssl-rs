/*
 * openssl-rs — Phase 25.16 historical CVE replay probe.
 *
 * Drives one historical memory-safety CVE's vulnerable input shape through the public C ABI
 * of whichever `libcrypto` the probe is linked against, and prints a one-line JSON transcript.
 * `forensics/tools/ms_cve_replay.py` compiles this probe against the candidate
 * (`artifacts/phase2`, the exact admitted candidate) and, for the cases whose positive control
 * is the vulnerable authority, against the affected historical prefix
 * (`forensics/authorities/prefix/openssl-<version>-historical`), then runs each case and
 * records the observed behaviour of both.
 *
 * The probe asserts nothing: it only reports what the linked library did (`accepted` is the
 * API's own success answer), so "the candidate is safe here" is derived from a recorded run
 * rather than from the probe's opinion. A case whose shape cannot be expressed through the
 * public ABI reports `unsupported: true` and the replay is recorded `UNKNOWN`, never a pass.
 *
 * Variants:
 *   candidate   -- drive the linked library's public entry point for the case.
 *   control     -- the deliberately-broken variant embedded for the cases whose control is not
 *                  an authority build (the pre-fix mechanism, in the same input shape).
 *
 * Build (inside the court only):
 *   gcc -O1 -w -I <prefix>/include -o probe cve_replay_probe.c \
 *       -L <prefix>/lib -lcrypto -Wl,-rpath,<prefix>/lib
 * Run:
 *   probe <case> <variant>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* One transcript line. Strings here are fixed literals, so no JSON escaping is needed. */
static void emit(const char *case_id, const char *variant, int has_accepted,
                 int accepted, const char *detail)
{
    if (has_accepted)
        printf("{\"case\":\"%s\",\"variant\":\"%s\",\"accepted\":%d,\"detail\":\"%s\"}\n",
               case_id, variant, accepted ? 1 : 0, detail);
    else
        printf("{\"case\":\"%s\",\"variant\":\"%s\",\"unsupported\":true}\n", case_id, variant);
    fflush(stdout);
}

/*
 * CVE-2024-9143 — low-level invalid GF(2^m) parameters lead to OOB memory access.
 *
 * The advisory's shape: a low-level GF(2^m) API called with an explicit field polynomial that
 * has a zero constant term (`x^8 + x^4`, an even value), which the pre-fix `BN_GF2m_poly2arr`
 * accepted. The fix refuses a non-odd modulus; the vulnerable authority proceeds into the
 * reducer. `BN_GF2m_mod_sqrt` is one of the affected wrappers.
 */
static void case_gf2m(const char *variant)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new(), *a = BN_new(), *r = BN_new();
    int ret;
    (void)variant;
    if (ctx == NULL || p == NULL || a == NULL || r == NULL) {
        emit("CVE-2024-9143", "candidate", 1, 0, "setup-refused");
        return;
    }
    BN_set_bit(p, 8);
    BN_set_bit(p, 4);          /* x^8 + x^4: the constant term is absent (even). */
    BN_set_word(a, 3);
    ret = BN_GF2m_mod_sqrt(r, a, p, ctx);
    emit("CVE-2024-9143", "candidate", 1, ret == 1, ret == 1 ? "accepted" : "refused");
}

/*
 * CVE-2024-0727 — PKCS12 decoding crashes.
 *
 * The advisory's shape: a PKCS12 structure that the specification allows to be NULL, reached
 * through `PKCS12_unpack_p7data`. The pre-fix code dereferences the absent octet string; the
 * candidate refuses it. The vulnerable authority faults here, which is the control.
 */
static void case_pkcs12(const char *variant)
{
    PKCS7 *p7;
    int n;
    (void)variant;
    p7 = PKCS7_new();
    if (p7 == NULL || PKCS7_set_type(p7, NID_pkcs7_data) != 1) {
        emit("CVE-2024-0727", "candidate", 1, 0, "setup-refused");
        return;
    }
    ASN1_OCTET_STRING_free(p7->d.data);
    p7->d.data = NULL;         /* the NULL field the advisory names */
    n = PKCS12_unpack_p7data(p7);
    emit("CVE-2024-0727", "candidate", 1, n > 0, n > 0 ? "accepted" : "refused");
}

/*
 * CVE-2026-34180 — heap buffer over-read in ASN.1 content parsing.
 *
 * The advisory's shape: a DER primitive element whose four-byte length is 0x80000001 (> 2 GiB).
 * The pre-fix decoder truncates that length to a signed int and then scans the content for a
 * terminating zero byte with the truncated value, reading past the buffer. The candidate parses
 * the length into a u64 and bounds it against the input extent, so it refuses the element.
 *
 * The embedded `control` reproduces the truncated scan on the identical input; it faults, which
 * is what makes "the candidate does not exhibit it" falsifiable (the same shape against the
 * pre-fix mechanism is detected).
 */
static void case_asn1(const char *variant)
{
    unsigned char buf[23];
    buf[0] = 0x04;             /* primitive, universal, OCTET STRING */
    buf[1] = 0x84;             /* long form, four length bytes */
    buf[2] = 0x80; buf[3] = 0x00; buf[4] = 0x00; buf[5] = 0x01;   /* length = 0x80000001 */
    memset(buf + 6, 0x41, 17);

    if (strcmp(variant, "control") == 0) {
        /* The pre-fix mechanism truncates the four-byte length to a signed int and scans the
         * content for a terminating zero byte with it. The input is placed at the end of a page
         * that is followed by a PROT_NONE guard page, so the truncated (negative, hence huge)
         * scan length runs off the mapping and faults -- the observable the candidate's refusal
         * is measured against. */
        long pg = sysconf(_SC_PAGESIZE);
        int len = (int)(((unsigned)buf[2] << 24) | ((unsigned)buf[3] << 16)
                        | ((unsigned)buf[4] << 8) | (unsigned)buf[5]);
        unsigned char *base = mmap(NULL, (size_t)pg * 2, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        unsigned char *copy = base + pg - (long)sizeof(buf);
        if (base == MAP_FAILED)
            return;
        memcpy(copy, buf, sizeof(buf));
        if (mprotect(base + pg, (size_t)pg, PROT_NONE) != 0)
            return;
        { const unsigned char *hit = (const unsigned char *)memchr(copy + 6, 0, (size_t)len);
          emit("CVE-2026-34180", "control", 1, hit != NULL, "scanned"); }
        return;
    } else {
        const unsigned char *p = buf;
        ASN1_TYPE *t = d2i_ASN1_TYPE(NULL, &p, (long)sizeof(buf));
        emit("CVE-2026-34180", "candidate", 1, t != NULL, t != NULL ? "accepted" : "refused");
        if (t != NULL)
            ASN1_TYPE_free(t);
    }
}

int main(int argc, char **argv)
{
    const char *c, *v;
    if (argc < 3) {
        fprintf(stderr, "usage: probe <case> <variant>\n");
        return 2;
    }
    c = argv[1];
    v = argv[2];

    if (strcmp(c, "gf2m_invalid_field_polynomial") == 0)
        case_gf2m(v);
    else if (strcmp(c, "pkcs12_null_octet_string") == 0)
        case_pkcs12(v);
    else if (strcmp(c, "asn1_oversized_length") == 0)
        case_asn1(v);
    else if (strcmp(c, "x509_x400_general_name") == 0
             || strcmp(c, "cms_aead_parameters") == 0
             || strcmp(c, "cms_key_unwrap_aead") == 0
             || strcmp(c, "dtls_retransmission") == 0)
        emit(c, v, 0, 0, "");   /* the shape is not expressible through the public ABI */
    else {
        fprintf(stderr, "unknown case: %s\n", c);
        return 2;
    }
    return 0;
}
