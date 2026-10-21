/*
 * Phase-25 L7 workload for the library-only `minizip-ng` family.
 *
 * minizip-ng ships no program of its own. This harness writes a one-entry
 * archive whose content is encrypted with WinZip AES-256 through
 * minizip-ng's OpenSSL crypto backend, reads it back with the right password,
 * and requires the wrong password to fail.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <mz.h>
#include <mz_strm.h>
#include <mz_zip.h>
#include <mz_zip_rw.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char PAYLOAD[] = "phase25-l7-minizip-ng-aes256-payload\n";
static const char PASSWORD[] = "phase25-l7-secret";
static const char ENTRY[] = "payload.txt";
static const char ARCHIVE[] = "l7-minizip-ng.zip";

int main(int argc, char **argv)
{
    void *writer = NULL, *reader = NULL;
    mz_zip_file info;
    char buf[256];
    int32_t n;
    int rc = 1;

    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("minizip-ng-l7-harness\n");
        return 0;
    }

    unlink(ARCHIVE);
    memset(&info, 0, sizeof(info));
    info.filename = ENTRY;
    info.compression_method = MZ_COMPRESS_METHOD_DEFLATE;

    writer = mz_zip_writer_create();
    if (writer == NULL)
        goto out;
    mz_zip_writer_set_password(writer, PASSWORD);
    mz_zip_writer_set_aes(writer, 1);
    mz_zip_writer_set_compress_method(writer, MZ_COMPRESS_METHOD_DEFLATE);
    if (mz_zip_writer_open_file(writer, ARCHIVE, 0, 0) != MZ_OK)
        goto out;
    if (mz_zip_writer_add_buffer(writer, (void *)PAYLOAD, (int32_t)strlen(PAYLOAD), &info)
        != MZ_OK)
        goto out;
    if (mz_zip_writer_close(writer) != MZ_OK)
        goto out;
    mz_zip_writer_delete(&writer);
    printf("aes256_write=ok\n");

    reader = mz_zip_reader_create();
    if (reader == NULL)
        goto out;
    mz_zip_reader_set_password(reader, PASSWORD);
    if (mz_zip_reader_open_file(reader, ARCHIVE) != MZ_OK)
        goto out;
    if (mz_zip_reader_goto_first_entry(reader) != MZ_OK)
        goto out;
    if (mz_zip_reader_entry_open(reader) != MZ_OK)
        goto out;
    memset(buf, 0, sizeof(buf));
    n = mz_zip_reader_entry_read(reader, buf, (int32_t)sizeof(buf) - 1);
    mz_zip_reader_entry_close(reader);
    if (n != (int32_t)strlen(PAYLOAD) || memcmp(buf, PAYLOAD, strlen(PAYLOAD)) != 0)
        goto out;
    printf("aes256_read=ok\n");
    mz_zip_reader_delete(&reader);

    reader = mz_zip_reader_create();
    if (reader == NULL)
        goto out;
    mz_zip_reader_set_password(reader, "phase25-wrong-password");
    if (mz_zip_reader_open_file(reader, ARCHIVE) != MZ_OK)
        goto out;
    if (mz_zip_reader_goto_first_entry(reader) != MZ_OK)
        goto out;
    n = mz_zip_reader_entry_open(reader);
    if (n == MZ_OK) {
        memset(buf, 0, sizeof(buf));
        n = mz_zip_reader_entry_read(reader, buf, (int32_t)sizeof(buf) - 1);
        mz_zip_reader_entry_close(reader);
        if (n > 0 && (size_t)n == strlen(PAYLOAD) &&
            memcmp(buf, PAYLOAD, strlen(PAYLOAD)) == 0) {
            fprintf(stderr, "minizip-ng: the wrong password decrypted the entry\n");
            goto out;
        }
    }
    printf("wrong_password=rejected\n");
    rc = 0;
 out:
    if (reader != NULL)
        mz_zip_reader_delete(&reader);
    if (writer != NULL)
        mz_zip_writer_delete(&writer);
    unlink(ARCHIVE);
    return rc;
}
