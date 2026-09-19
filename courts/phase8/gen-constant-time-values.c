/*
 * Generate the constant-time helper expectations for `src/runtime/constant_time.rs` by compiling the
 * authority's own `include/internal/constant_time.h`. The transcription's oracle is the header it
 * transcribes, and the test records that provenance rather than claiming a property check it did not
 * perform.
 *
 * `ossl_inline` comes from `openssl/e_os2.h`, and `ossl_assert` is not used by any helper reported
 * here, so the header is includable on its own.
 */
#include <stdio.h>
#include "internal/constant_time.h"

int main(void)
{
    static const size_t inputs[] = {
        0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 257,
        65535, 65536, 0x7fffffffUL, 0x80000000UL, 0xffffffffUL,
        0x100000000UL, 0xffffffffffffffffUL,
    };
    static const unsigned char bytes[] = { 0, 1, 2, 0x7f, 0x80, 0xfe, 0xff };
    size_t i, j;
    unsigned char k;

    /* Every field is hex, including the expected mask, so the reader has one numeric base to
     * parse and a decimal-looking `255` can never be read as a hex literal. */
    printf("/* constant_time_eq_8_s: equality masks (0x00 or 0xff) */\n");
    for (i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++)
        for (j = 0; j < sizeof(inputs) / sizeof(inputs[0]); j++)
            printf("    (0x%zx, 0x%zx, 0x%02x),\n", inputs[i], inputs[j],
                   (unsigned)constant_time_eq_8_s(inputs[i], inputs[j]));

    printf("/* constant_time_ge_8_s: greater-or-equal masks (0x00 or 0xff) */\n");
    for (i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++)
        for (j = 0; j < sizeof(inputs) / sizeof(inputs[0]); j++)
            printf("    (0x%zx, 0x%zx, 0x%02x),\n", inputs[i], inputs[j],
                   (unsigned)constant_time_ge_8_s(inputs[i], inputs[j]));

    printf("/* constant_time_select_8, over (mask, a, b) triples in the byte domain */\n");
    for (i = 0; i < sizeof(bytes) / sizeof(bytes[0]); i++)
        for (j = 0; j < sizeof(bytes) / sizeof(bytes[0]); j++)
            for (k = 0; k < 2; k++) {
                unsigned char mask = k ? 0xff : 0x00;
                printf("    (0x%02x, 0x%02x, 0x%02x, 0x%02x),\n", mask, bytes[i], bytes[j],
                       constant_time_select_8(mask, bytes[i], bytes[j]));
            }

    /*
     * Masks that are **neither all-ones nor all-zeros**, which is the input the module's doc warns
     * a caller about. The expected values come from the header rather than from hand arithmetic,
     * because the hand-written form of this assertion was wrong the first time it was written: a
     * mask of `1` keeps bit 0 of `a` and every *other* bit of `b`, which is not `a` truncated.
     */
    {
        static const unsigned char odd_masks[] = { 1, 2, 0x7f, 0xfe };
        size_t m;

        printf("/* constant_time_select_8 with masks that are neither 0x00 nor 0xff */\n");
        for (m = 0; m < sizeof(odd_masks) / sizeof(odd_masks[0]); m++)
            for (i = 0; i < sizeof(bytes) / sizeof(bytes[0]); i++)
                for (j = 0; j < sizeof(bytes) / sizeof(bytes[0]); j++)
                    printf("    (0x%02x, 0x%02x, 0x%02x, 0x%02x),\n", odd_masks[m],
                           bytes[i], bytes[j],
                           constant_time_select_8(odd_masks[m], bytes[i], bytes[j]));
    }

    return 0;
}
