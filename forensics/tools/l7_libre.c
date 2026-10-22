/*
 * Phase-25 L7 workload for the `libre` family.
 *
 * libre's OpenSSL consumer path here is its SRTP implementation (src/srtp/srtp.c ->
 * src/srtp/stream.c: AES-CTR via EVP and HMAC-SHA1 via the OpenSSL HMAC interface). The harness
 * protects one fixed RTP packet with SRTP_AES_CM_128_HMAC_SHA1_80, unprotects it with a fresh
 * context and requires the original payload back, then flips a byte of the authentication tag:
 * decryption must fail with EAUTH. The same key and packet produce the same protected bytes, so
 * the observable is deterministic and the control is a genuine integrity check.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <re.h>

#include <stdio.h>
#include <string.h>

static const uint8_t KEY[30] = {
    0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0,
    0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39,
    0x0E, 0xC6, 0x37, 0x1B, 0x7A, 0x51, 0x2D, 0x94,
    0x0F, 0x63, 0x8C, 0x22, 0x5A, 0x71,
};

static const char PAYLOAD[] = "libre-l7-payload";

static struct mbuf *make_packet(void)
{
    struct rtp_header hdr;
    struct mbuf *mb;

    memset(&hdr, 0, sizeof(hdr));
    hdr.ver = RTP_VERSION;
    hdr.pt = 96;
    hdr.seq = 1234;
    hdr.ts = 0x01020304;
    hdr.ssrc = 0x11223344;

    mb = mbuf_alloc(256);
    if (!mb)
        return NULL;
    if (rtp_hdr_encode(mb, &hdr) != 0 ||
        mbuf_write_mem(mb, (const uint8_t *)PAYLOAD, sizeof(PAYLOAD) - 1) != 0) {
        mem_deref(mb);
        return NULL;
    }
    mbuf_set_pos(mb, 0);
    return mb;
}

int main(int argc, char **argv)
{
    struct srtp *enc = NULL, *dec = NULL;
    struct mbuf *mb = NULL, *copy = NULL;
    uint8_t protected_pkt[256];
    size_t protected_len;
    int encrypt_ok = 0, roundtrip = 0, tamper = 0, ok;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("libre-l7-harness 1\n");
        return 0;
    }
    if (libre_init() != 0)
        return 1;

    mb = make_packet();
    if (!mb)
        goto out;
    if (srtp_alloc(&enc, SRTP_AES_CM_128_HMAC_SHA1_80, KEY, sizeof(KEY), 0) != 0)
        goto out;
    if (srtp_encrypt(enc, mb) != 0)
        goto out;
    protected_len = mbuf_get_left(mb);
    if (protected_len > sizeof(protected_pkt))
        goto out;
    memcpy(protected_pkt, mbuf_buf(mb), protected_len);
    encrypt_ok = (protected_len == 12 + sizeof(PAYLOAD) - 1 + 10 &&
                  memcmp(protected_pkt + 12, PAYLOAD, sizeof(PAYLOAD) - 1) != 0);
    printf("srtp_encrypt=%s\n", encrypt_ok ? "ok" : "failed");

    copy = mbuf_alloc(protected_len + 16);
    if (!copy || mbuf_write_mem(copy, protected_pkt, protected_len) != 0)
        goto out;
    mbuf_set_pos(copy, 0);
    if (srtp_alloc(&dec, SRTP_AES_CM_128_HMAC_SHA1_80, KEY, sizeof(KEY), 0) != 0)
        goto out;
    if (srtp_decrypt(dec, copy) == 0 &&
        memcmp(mbuf_buf(copy) + 12, PAYLOAD, sizeof(PAYLOAD) - 1) == 0)
        roundtrip = 1;
    printf("srtp_roundtrip=%s\n", roundtrip ? "ok" : "failed");

    memset(copy->buf, 0, copy->size);
    copy->pos = 0;
    copy->end = 0;
    if (mbuf_write_mem(copy, protected_pkt, protected_len) != 0)
        goto out;
    copy->buf[copy->end - 1] ^= 0xff;
    copy->pos = 0;
    {
        struct srtp *bad = NULL;
        if (srtp_alloc(&bad, SRTP_AES_CM_128_HMAC_SHA1_80, KEY, sizeof(KEY), 0) == 0) {
            tamper = (srtp_decrypt(bad, copy) != 0);
            mem_deref(bad);
        }
    }
    printf("tamper=%s\n", tamper ? "rejected" : "accepted");

    ok = encrypt_ok && roundtrip && tamper;
out:
    mem_deref(copy);
    mem_deref(mb);
    mem_deref(dec);
    mem_deref(enc);
    libre_close();
    printf("result=%s\n", ok ? "ok" : "fail");
    return ok ? 0 : 1;
}
