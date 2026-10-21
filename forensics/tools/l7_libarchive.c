/*
 * Phase-24.7 L7 workload for the library-only `libarchive` family.
 *
 * libarchive ships no executable of its own, so the admitted workload is this
 * small program: libarchive writes an in-memory tar archive holding a payload
 * and its SHA-256 digest, computed through libcrypto's EVP digest API, then
 * reads the archive back and verifies the digest. In tamper mode one payload
 * byte inside the archive is flipped; the digest check must reject it.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char PAYLOAD[] = "phase24-libarchive-l7-payload\n";

static int sha256_hex(const void *data, size_t len, char *out, size_t outlen)
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    size_t i;

    if (md == NULL)
        return -1;
    if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md, data, len) != 1 ||
        EVP_DigestFinal_ex(md, digest, &dlen) != 1) {
        EVP_MD_CTX_free(md);
        return -1;
    }
    EVP_MD_CTX_free(md);
    if (outlen < (size_t)dlen * 2 + 1)
        return -1;
    for (i = 0; i < dlen; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[dlen * 2] = '\0';
    return 0;
}

static int append_entry(struct archive *a, const char *name,
                        const void *data, size_t len)
{
    struct archive_entry *entry = archive_entry_new();
    int rc = -1;

    if (entry == NULL)
        return -1;
    archive_entry_set_pathname(entry, name);
    archive_entry_set_size(entry, (la_int64_t)len);
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);
    if (archive_write_header(a, entry) != ARCHIVE_OK)
        goto out;
    if (len > 0 && archive_write_data(a, data, len) != (la_ssize_t)len)
        goto out;
    rc = 0;
 out:
    archive_entry_free(entry);
    return rc;
}

static int build_archive(unsigned char *buf, size_t cap, size_t *used)
{
    struct archive *a = archive_write_new();
    char sums[128];
    int rc = -1;

    if (a == NULL)
        return -1;
    if (sha256_hex(PAYLOAD, strlen(PAYLOAD), sums, sizeof(sums)) != 0)
        goto out;
    if (archive_write_set_format_pax_restricted(a) != ARCHIVE_OK)
        goto out;
    if (archive_write_open_memory(a, buf, cap, used) != ARCHIVE_OK)
        goto out;
    if (append_entry(a, "payload.txt", PAYLOAD, strlen(PAYLOAD)) != 0)
        goto out;
    if (append_entry(a, "SHA256SUMS", sums, strlen(sums)) != 0)
        goto out;
    if (archive_write_close(a) != ARCHIVE_OK)
        goto out;
    rc = 0;
 out:
    archive_write_free(a);
    return rc;
}

static int read_entry(struct archive *a, struct archive_entry *entry,
                      char *out, size_t cap)
{
    size_t off = 0;
    la_ssize_t n;
    char chunk[256];

    while ((n = archive_read_data(a, chunk, sizeof(chunk))) > 0) {
        if (off + (size_t)n >= cap)
            return -1;
        memcpy(out + off, chunk, (size_t)n);
        off += (size_t)n;
    }
    if (n < 0)
        return -1;
    out[off] = '\0';
    (void)entry;
    return (int)off;
}

static int read_archive(const unsigned char *buf, size_t used,
                        char *payload, size_t payload_cap,
                        char *sums, size_t sums_cap)
{
    struct archive *a = archive_read_new();
    struct archive_entry *entry;
    int rc_read, rc = -1;

    payload[0] = '\0';
    sums[0] = '\0';
    if (a == NULL)
        return -1;
    if (archive_read_support_format_tar(a) != ARCHIVE_OK)
        goto out;
    if (archive_read_open_memory(a, buf, used) != ARCHIVE_OK)
        goto out;
    while ((rc_read = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);

        if (name != NULL && strcmp(name, "payload.txt") == 0) {
            if (read_entry(a, entry, payload, payload_cap) < 0)
                goto out;
        } else if (name != NULL && strcmp(name, "SHA256SUMS") == 0) {
            if (read_entry(a, entry, sums, sums_cap) < 0)
                goto out;
        } else {
            archive_read_data_skip(a);
        }
    }
    if (rc_read != ARCHIVE_EOF)
        goto out;
    rc = 0;
 out:
    archive_read_free(a);
    return rc;
}

int main(int argc, char **argv)
{
    unsigned char buf[16384];
    char payload[512], sums[512], digest[128];
    size_t used = 0, plen = strlen(PAYLOAD);
    int i, tamper = 0, rejected = 0, read_ok, digest_ok;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("libarchive-l7-harness 1\n");
            return 0;
        } else if (strcmp(argv[i], "--tamper") == 0) {
            tamper = 1;
        } else {
            fprintf(stderr, "usage: %s [--tamper]\n", argv[0]);
            return 3;
        }
    }
    if (build_archive(buf, sizeof(buf), &used) != 0) {
        fprintf(stderr, "harness: archive creation failed\n");
        return 1;
    }
    if (tamper) {
        unsigned char *where = memmem(buf, used, PAYLOAD, plen);

        if (where == NULL) {
            fprintf(stderr, "harness: payload bytes not found in the archive\n");
            return 1;
        }
        where[0] ^= 0x01;
    }
    read_ok = read_archive(buf, used, payload, sizeof(payload),
                           sums, sizeof(sums)) == 0;
    if (!read_ok) {
        /* A tampered header/stream is rejected by the reader itself. */
        rejected = tamper;
        printf("harness=libarchive-l7\n");
        printf("version=1\n");
        printf("archive=rejected\n");
        printf("digest=failed\n");
        printf("tampered=%s\n", tamper ? "rejected" : "not-run");
        printf("result=%s\n", tamper ? "ok" : "fail");
        return tamper ? 0 : 1;
    }
    if (sha256_hex(payload, strlen(payload), digest, sizeof(digest)) != 0) {
        fprintf(stderr, "harness: digest computation failed\n");
        return 1;
    }
    digest_ok = (strncmp(digest, sums, strlen(digest)) == 0);
    if (tamper)
        rejected = (strcmp(payload, PAYLOAD) != 0) && !digest_ok;

    printf("harness=libarchive-l7\n");
    printf("version=1\n");
    printf("archive=read\n");
    printf("digest=%s\n", digest_ok ? "ok" : "failed");
    printf("tampered=%s\n", tamper ? (rejected ? "rejected" : "accepted") : "not-run");
    if (tamper) {
        printf("result=%s\n", rejected ? "ok" : "fail");
        return rejected ? 0 : 2;
    }
    if (strcmp(payload, PAYLOAD) == 0 && digest_ok) {
        printf("result=ok\n");
        return 0;
    }
    printf("result=fail\n");
    return 1;
}
