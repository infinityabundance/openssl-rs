/*
 * PFP-70 table-AES reference throughput, same block-API loop shape as
 * examples/pfp63_bench.rs. Linked against the pinned authority
 * (openssl-3.6.4-production). Run with OPENSSL_ia32cap=0x0:0x0 to force the
 * authority's portable Te/Td-table arm on an AES-NI host.
 *
 * This is a measurement harness, not product code.
 */
#define _GNU_SOURCE
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

int main(void) {
    const char *e = getenv("PFP70_ITERS");
    long iters = e ? strtol(e, NULL, 10) : 3000000L;
    unsigned char key[32], in[16], out[16];
    for (int i = 0; i < 32; i++) key[i] = (unsigned char)i;
    for (int i = 0; i < 16; i++) in[i] = (unsigned char)(i * 17);

    for (int bits = 128; bits <= 256; bits += 64) {
        AES_KEY ek, dk;
        if (AES_set_encrypt_key(key, bits, &ek) != 0) return 2;
        if (AES_set_decrypt_key(key, bits, &dk) != 0) return 2;
        volatile unsigned char sink;
        double t = now();
        for (long i = 0; i < iters; i++) AES_encrypt(in, out, &ek);
        double se = now() - t;
        sink = out[0];
        t = now();
        for (long i = 0; i < iters; i++) AES_decrypt(in, out, &dk);
        double sd = now() - t;
        sink = out[0];
        (void)sink;
        double enc = (double)iters * 16.0 / se / (1024.0 * 1024.0);
        double dec = (double)iters * 16.0 / sd / (1024.0 * 1024.0);
        printf("AES-%d: encrypt %.1f MB/s, decrypt %.1f MB/s\n", bits, enc, dec);
    }
    return 0;
}
