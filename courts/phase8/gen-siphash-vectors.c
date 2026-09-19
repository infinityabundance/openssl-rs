/* Generate the SipHash-2-4 expectations for src/mac/siphash.rs's unit test by compiling the
 * authority's own crypto/siphash/siphash.c -- the transcription's oracle is the unit it
 * transcribes, and the test records that provenance rather than claiming the paper's vectors. */
#include <stdio.h>
#include <string.h>
#include "crypto/siphash.h"

int main(void)
{
    unsigned char key[16];
    unsigned char msg[64];
    unsigned char out[8];
    int i, n;

    for (i = 0; i < 16; i++)
        key[i] = (unsigned char)i;
    for (i = 0; i < 64; i++)
        msg[i] = (unsigned char)i;

    for (n = 0; n < 64; n++) {
        SIPHASH ctx;
        memset(&ctx, 0, sizeof(ctx));
        SipHash_set_hash_size(&ctx, 8);
        SipHash_Init(&ctx, key, 0, 0);
        SipHash_Update(&ctx, msg, (size_t)n);
        memset(out, 0, sizeof(out));
        SipHash_Final(&ctx, out, 8);
        printf("            (%d, [", n);
        for (i = 0; i < 8; i++)
            printf("0x%02x%s", out[i], i == 7 ? "" : ", ");
        printf("]),\n");
    }
    return 0;
}
