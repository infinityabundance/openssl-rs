/*
 * Phase-25 L7 workload for the library-only `libzip` family.
 *
 * libzip ships no executable. This program writes a one-entry archive whose
 * content is encrypted with AES-256 through libzip's OpenSSL backend, reads
 * it back with the right password, and requires the wrong password to fail.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zip.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char PAYLOAD[] = "phase25-l7-libzip-aes256-payload\n";
static const char PASSWORD[] = "phase25-l7-secret";
static const char ENTRY[] = "payload.txt";
static const char ARCHIVE[] = "l7-aes256.zip";

int main(int argc, char **argv)
{
    zip_t *za = NULL, *zr = NULL;
    zip_source_t *src = NULL;
    zip_file_t *zf = NULL;
    zip_int64_t idx;
    zip_int64_t n;
    char buf[256];
    int err = 0, rc = 1;

    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("libzip-l7-harness (libzip)\n");
        return 0;
    }

    unlink(ARCHIVE);
    za = zip_open(ARCHIVE, ZIP_CREATE | ZIP_TRUNCATE, &err);
    if (za == NULL)
        goto out;
    src = zip_source_buffer(za, PAYLOAD, strlen(PAYLOAD), 0);
    if (src == NULL)
        goto out;
    idx = zip_file_add(za, ENTRY, src, ZIP_FL_OVERWRITE);
    if (idx < 0)
        goto out;
    if (zip_file_set_encryption(za, (zip_uint64_t)idx, ZIP_EM_AES_256, PASSWORD) != 0)
        goto out;
    if (zip_close(za) != 0)
        goto out;
    za = NULL;
    printf("aes256_write=ok\n");

    zr = zip_open(ARCHIVE, ZIP_RDONLY, &err);
    if (zr == NULL)
        goto out;
    zf = zip_fopen_encrypted(zr, ENTRY, 0, PASSWORD);
    if (zf == NULL)
        goto out;
    n = zip_fread(zf, buf, sizeof(buf));
    zip_fclose(zf);
    zf = NULL;
    if (n != (zip_int64_t)strlen(PAYLOAD) ||
        memcmp(buf, PAYLOAD, strlen(PAYLOAD)) != 0)
        goto out;
    printf("aes256_read=ok\n");

    zf = zip_fopen_encrypted(zr, ENTRY, 0, "phase25-wrong-password");
    if (zf != NULL) {
        n = zip_fread(zf, buf, sizeof(buf));
        zip_fclose(zf);
        zf = NULL;
        if (n >= 0 && (size_t)n == strlen(PAYLOAD) &&
            memcmp(buf, PAYLOAD, strlen(PAYLOAD)) == 0) {
            fprintf(stderr, "libzip: the wrong password decrypted the entry\n");
            goto out;
        }
    }
    printf("wrong_password=rejected\n");
    rc = 0;
 out:
    if (zf != NULL)
        zip_fclose(zf);
    if (zr != NULL)
        zip_close(zr);
    if (za != NULL)
        zip_close(za);
    unlink(ARCHIVE);
    return rc;
}
