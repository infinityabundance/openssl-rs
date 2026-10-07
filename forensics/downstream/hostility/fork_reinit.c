/*
 * 24.10 hostility probe: **fork / reinit** — a process that has already initialised OpenSSL forks,
 * the child re-initialises the library and runs a digest and a random draw, and the parent does the
 * same after the child exits. This is the long-lived-process / fork-reinitialisation contract a
 * daemon-like consumer depends on.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hostility_common.h"
#include <sys/wait.h>
#include <unistd.h>

static int digest_ok(const char *tag)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (c == NULL)
        return 0;
    if (!EVP_DigestInit_ex(c, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(c);
        return 0;
    }
    EVP_DigestUpdate(c, tag, strlen(tag));
    EVP_DigestFinal_ex(c, md, &len);
    EVP_MD_CTX_free(c);
    return len == 32;
}

static int copy_ok(void)
{
    EVP_MD_CTX *a = EVP_MD_CTX_new();
    EVP_MD_CTX *b = EVP_MD_CTX_new();
    if (a == NULL || b == NULL) {
        EVP_MD_CTX_free(a);
        EVP_MD_CTX_free(b);
        return 0;
    }
    EVP_DigestInit_ex(a, EVP_sha256(), NULL);
    EVP_DigestUpdate(a, "c", 1);
    int ok = EVP_MD_CTX_copy(b, a) == 1;
    EVP_MD_CTX_free(a);
    EVP_MD_CTX_free(b);
    return ok;
}

int main(void)
{
    hostility_banner("fork-reinit");
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ATFORK, NULL);

    unsigned char r[16];
    printf("parent_rand=%d\n", RAND_bytes(r, sizeof(r)) == 1);
    printf("parent_priv_rand=%d\n", RAND_priv_bytes(r, sizeof(r)) == 1);
    printf("ctx_copy_ok=%d\n", copy_ok());

    pid_t pid = fork();
    if (pid < 0)
        hostility_fail("fork");
    if (pid == 0) {
        OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
        unsigned char cr[16];
        printf("child_digest_ok=%d\n", digest_ok("child"));
        printf("child_rand=%d\n", RAND_bytes(cr, sizeof(cr)) == 1);
        fflush(stdout);
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    printf("child_status=%d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    printf("parent_digest_ok=%d\n", digest_ok("parent"));
    hostility_ok();
    return 0;
}
