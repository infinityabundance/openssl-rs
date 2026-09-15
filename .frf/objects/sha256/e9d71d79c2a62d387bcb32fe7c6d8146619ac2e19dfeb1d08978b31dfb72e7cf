/*
 * openssl-rs — RT-PEM: the PEM header formatters, differentially.
 *
 * `PEM_proc_type` and `PEM_dek_info` are the two `pem.h` exports that need nothing
 * beyond `BIO_snprintf`, which is why they are Phase 5's and the rest of the
 * stratum is not. Both *append* to a caller's `PEM_BUFSIZE` buffer, and that
 * accumulation — `Proc-Type` first, then `DEK-Info` — is what
 * `PEM_ASN1_write_bio_internal` builds before it writes an item.
 *
 * What this probe establishes:
 *
 *   a.*  the four `PEM_proc_type` answers: the three named types and `BAD-TYPE` for
 *        everything else, including `PEM_TYPE_CLEAR`, which has no arm of its own
 *   b.*  each of them appends at the end of what the buffer already held, and the
 *        appended text is exactly `Proc-Type: 4,<name>\n`
 *   c.*  `PEM_dek_info` writes `DEK-Info: <type>,` then two uppercase hex digits per
 *        byte, then a newline, and it masks each byte with `0xff` so a negative
 *        `char` still renders as two digits
 *   d.*  the two together are the header `PEM_ASN1_write_bio_internal` assembles, in
 *        that order, in one buffer
 *   e.*  the newline is conditional on more than one byte of room remaining: with
 *        two bytes it is written, with one or none it is not, and the truncation of
 *        a header that does not fit lands at the same byte on both sides
 *   f.*  a `len` of zero writes the separator and the newline and no digits
 *
 * The near-full-buffer cases stop short of the one arrangement the authority cannot
 * perform: with exactly one byte of room and a second byte still to encode it calls
 * `BIO_snprintf` with a negative length converted to `size_t` and writes past the
 * buffer. That region is recorded as D-PEM-1 and is not claimable, so the probe does
 * not ask for it.
 *
 * Determinism: key=value per line, every result rendered as its length, its text with
 * control bytes escaped, and the tail in hex. Nothing depends on an address.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/bio.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <string.h>

#define BUFSZ 1024

/* Print the buffer's string form, its length and its hex tail. */
static void show(const char *key, const char *buf)
{
    size_t n = strlen(buf);
    size_t i;

    printf("%s.len=%zu\n", key, n);
    printf("%s=\"", key);
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)buf[i];

        if (c == '\n')
            printf("\\n");
        else if (c >= 0x20 && c < 0x7f)
            printf("%c", c);
        else
            printf("\\x%02x", c);
    }
    printf("\"\n");
}

static void show_hex(const char *key, const char *buf, int from, int n)
{
    int i;

    printf("%s=", key);
    for (i = 0; i < n; i++)
        printf("%02x", (unsigned char)buf[from + i]);
    printf("\n");
}

/* ------------------------------------------------------------- a.b. proc type */

static const int proc_types[] = { PEM_TYPE_ENCRYPTED, PEM_TYPE_MIC_CLEAR,
    PEM_TYPE_MIC_ONLY, PEM_TYPE_CLEAR, 0, -1, 99 };

static void part_proc_type(void)
{
    size_t i;

    for (i = 0; i < sizeof(proc_types) / sizeof(proc_types[0]); i++) {
        char buf[BUFSZ];
        char key[64];

        memset(buf, 0, sizeof(buf));
        PEM_proc_type(buf, proc_types[i]);
        sprintf(key, "a.type_%d", proc_types[i]);
        show(key, buf);
    }

    /* Appending: the buffer already holds a header line. */
    {
        char buf[BUFSZ];

        memset(buf, 0, sizeof(buf));
        strcpy(buf, "Existing: 1\n");
        PEM_proc_type(buf, PEM_TYPE_ENCRYPTED);
        PEM_proc_type(buf, PEM_TYPE_MIC_ONLY);
        show("b.appended_twice", buf);
    }
}

/* --------------------------------------------------------------- c. dek info */

static void part_dek_info(void)
{
    unsigned char iv[16];
    int i;

    for (i = 0; i < (int)sizeof(iv); i++)
        iv[i] = (unsigned char)(i * 16 + i);

    /* 16 bytes, the usual IV length. */
    {
        char buf[BUFSZ];

        memset(buf, 0, sizeof(buf));
        PEM_dek_info(buf, "AES-128-CBC", 16, (const char *)iv);
        show("c.aes128_16", buf);
    }

    /* Eight bytes, a DES IV. */
    {
        char buf[BUFSZ];

        memset(buf, 0, sizeof(buf));
        PEM_dek_info(buf, "DES-EDE3-CBC", 8, (const char *)iv);
        show("c.des3_8", buf);
    }

    /* Zero bytes: the separator and the newline, no digits. */
    {
        char buf[BUFSZ];

        memset(buf, 0, sizeof(buf));
        PEM_dek_info(buf, "X", 0, (const char *)iv);
        show("c.zero_len", buf);
    }

    /* A high-bit byte, to show the `0xff &` mask. */
    {
        char buf[BUFSZ];
        static const unsigned char hi[4] = { 0x00, 0x7f, 0x80, 0xff };

        memset(buf, 0, sizeof(buf));
        PEM_dek_info(buf, "T", 4, (const char *)hi);
        show("c.high_bits", buf);
    }

    /* Appending onto a prefix, which is how the header is really built. */
    {
        char buf[BUFSZ];

        memset(buf, 0, sizeof(buf));
        strcpy(buf, "Proc-Type: 4,ENCRYPTED\n");
        PEM_dek_info(buf, "AES-256-CBC", 16, (const char *)iv);
        show("c.appended", buf);
    }
}

/* --------------------------------------------------------- d. the real header */

static void part_header(void)
{
    char buf[BUFSZ];
    unsigned char iv[8];
    int i;

    for (i = 0; i < (int)sizeof(iv); i++)
        iv[i] = (unsigned char)(0x10 + i);

    memset(buf, 0, sizeof(buf));
    PEM_proc_type(buf, PEM_TYPE_ENCRYPTED);
    PEM_dek_info(buf, "DES-CBC", (int)sizeof(iv), (const char *)iv);
    show("d.header", buf);
}

/* ------------------------------------------------------- e.f. the room rules */

static void part_room(void)
{
    /* 1010 used, header is 12 bytes plus its NUL: two bytes of room remain after it,
     * so the newline is written and two digits fit. */
    {
        char buf[BUFSZ];
        unsigned char b[2] = { 0xab, 0xcd };

        memset(buf, 0, sizeof(buf));
        memset(buf, 'x', 1010);
        buf[1010] = '\0';
        PEM_dek_info(buf, "X", 2, (const char *)b);
        printf("e.room2.len=%zu\n", strlen(buf));
        show_hex("e.room2.tail", buf, 1010, 14);
    }

    /* 1011 used: one byte of room after the header, one digit encodes. */
    {
        char buf[BUFSZ];
        unsigned char b[1] = { 0xab };

        memset(buf, 0, sizeof(buf));
        memset(buf, 'x', 1011);
        buf[1011] = '\0';
        PEM_dek_info(buf, "X", 1, (const char *)b);
        printf("e.room1.len=%zu\n", strlen(buf));
        show_hex("e.room1.tail", buf, 1011, 13);
    }

    /* 1013 used: the header itself does not fit, so it is truncated to the ten bytes
     * that do and nothing follows. No digits, so the loop is never entered. */
    {
        char buf[BUFSZ];

        memset(buf, 0, sizeof(buf));
        memset(buf, 'x', 1013);
        buf[1013] = '\0';
        PEM_dek_info(buf, "X", 0, NULL);
        printf("e.room0.len=%zu\n", strlen(buf));
        show_hex("e.room0.tail", buf, 1013, 11);
    }

    /* A prefix that already fills all but one byte of the header buffer: the
     * remainder is one, so `BIO_snprintf` writes the terminating NUL and nothing
     * else, and the buffer is unchanged in length. */
    {
        char buf[BUFSZ];

        memset(buf, 0, sizeof(buf));
        memset(buf, 'y', BUFSZ - 1);
        buf[BUFSZ - 1] = '\0';
        PEM_proc_type(buf, PEM_TYPE_ENCRYPTED);
        printf("f.full.len=%zu\n", strlen(buf));
        show_hex("f.full.tail", buf, BUFSZ - 8, 8);
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    part_proc_type();
    part_dek_info();
    part_header();
    part_room();

    printf("done=1\n");
    return 0;
}
