/*
 * 24.10 hostility probe: **threading** — four threads that share a `CRYPTO_RWLOCK` through the
 * subject's own thread abstraction, run a `CRYPTO_ONCE` initialiser exactly once, take the current
 * thread id, and each run a digest. It exercises the library's threading contract under concurrency.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hostility_common.h"
#include <openssl/crypto.h>
#include <pthread.h>

static CRYPTO_ONCE once = CRYPTO_ONCE_STATIC_INIT;
static int once_count = 0;
static CRYPTO_RWLOCK *shared_lock = NULL;

static void once_fn(void)
{
    once_count++;
}

static void printf_once_id(CRYPTO_THREAD_ID id)
{
    (void)id;
}

static void *worker(void *arg)
{
    long *acc = (long *)arg;
    if (!CRYPTO_THREAD_run_once(&once, once_fn))
        return (void *)1;
    printf_once_id(CRYPTO_THREAD_get_current_id());
    if (shared_lock == NULL)
        return (void *)1;
    for (int i = 0; i < 2000; i++) {
        if (!CRYPTO_THREAD_write_lock(shared_lock))
            break;
        (*acc)++;
        CRYPTO_THREAD_unlock(shared_lock);
    }

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (c == NULL)
        return (void *)1;
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    EVP_DigestUpdate(c, "t", 1);
    EVP_DigestFinal_ex(c, md, &len);
    EVP_MD_CTX_free(c);
    return len == 32 ? NULL : (void *)1;
}

int main(void)
{
    hostility_banner("threading");
    shared_lock = CRYPTO_THREAD_lock_new();
    if (shared_lock == NULL)
        hostility_fail("CRYPTO_THREAD_lock_new");
    pthread_t t[4];
    long acc = 0;
    for (int i = 0; i < 4; i++)
        pthread_create(&t[i], NULL, worker, &acc);
    int bad = 0;
    for (int i = 0; i < 4; i++) {
        void *r = NULL;
        pthread_join(t[i], &r);
        if (r != NULL)
            bad++;
    }
    printf("accumulator=%ld\n", acc);
    printf("once_count=%d\n", once_count);
    printf("threads_failed=%d\n", bad);
    CRYPTO_THREAD_lock_free(shared_lock);
    if (bad != 0 || once_count != 1 || acc != 4L * 2000L)
        hostility_fail("threading contract");
    hostility_ok();
    return 0;
}
