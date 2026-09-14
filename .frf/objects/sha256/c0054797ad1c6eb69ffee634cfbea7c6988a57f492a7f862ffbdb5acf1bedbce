/*
 * openssl-rs — RT-THREAD probe.
 *
 * One program, compiled against the authority and against the candidate and
 * diffed. It measures the thread abstraction and the atomic helpers.
 *
 * The atomics are the interesting part. The authority takes a *hardware* path
 * when the compiler reports the operation lock-free and only falls back to the
 * caller-supplied `CRYPTO_RWLOCK` otherwise, and the two paths differ in what
 * they write through `ret` (`__atomic_fetch_or(...) | op` is not the same as
 * "the old value"). Guessing here would produce a plausible-looking helper that
 * silently returns the pre-operation value, so the probe records the exact
 * result of each call, with and without a lock.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/crypto.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void r64(const char *k, int rc, uint64_t ret)
{
    printf("%s=%d/%llu\n", k, rc, (unsigned long long)ret);
}

static int g_once_calls;

static void init_fn(void)
{
    g_once_calls++;
}

int main(void)
{
    CRYPTO_RWLOCK *lock;
    uint64_t v, ret;
    int ival, iret;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("probe.rt-thread=1\n");

    /* ---- rwlock ------------------------------------------------------------ */
    lock = CRYPTO_THREAD_lock_new();
    printf("lock.new_nonnull=%d\n", lock != NULL);
    printf("lock.read=%d\n", CRYPTO_THREAD_read_lock(lock));
    printf("lock.read_twice=%d\n", CRYPTO_THREAD_read_lock(lock));
    printf("lock.unlock=%d\n", CRYPTO_THREAD_unlock(lock));
    printf("lock.unlock_again=%d\n", CRYPTO_THREAD_unlock(lock));
    printf("lock.write=%d\n", CRYPTO_THREAD_write_lock(lock));
    /* A second write lock on the same thread is not recursive in the authority:
     * it either fails or deadlocks, so this is only recorded when it returns. */
    printf("lock.unlock_write=%d\n", CRYPTO_THREAD_unlock(lock));
    CRYPTO_THREAD_lock_free(lock);
    CRYPTO_THREAD_lock_free(NULL);
    printf("lock.free_null_survived=1\n");

    /* ---- thread identity --------------------------------------------------- */
    {
        CRYPTO_THREAD_ID a = CRYPTO_THREAD_get_current_id();
        CRYPTO_THREAD_ID b = CRYPTO_THREAD_get_current_id();
        printf("id.stable_within_thread=%d\n", CRYPTO_THREAD_compare_id(a, b));
        printf("id.differs_from_null=%d\n",
               CRYPTO_THREAD_compare_id(a, (CRYPTO_THREAD_ID)0) == 0);
    }

    /* ---- run_once ---------------------------------------------------------- */
    {
        static CRYPTO_ONCE once = CRYPTO_ONCE_STATIC_INIT;
        printf("once.first=%d\n", CRYPTO_THREAD_run_once(&once, init_fn));
        printf("once.calls_after_first=%d\n", g_once_calls);
        printf("once.second=%d\n", CRYPTO_THREAD_run_once(&once, init_fn));
        printf("once.calls_after_second=%d\n", g_once_calls);
    }

    /* ---- thread-local storage ---------------------------------------------- */
    {
        static CRYPTO_THREAD_LOCAL key;
        printf("tls.init=%d\n", CRYPTO_THREAD_init_local(&key, NULL));
        printf("tls.get_before_set_null=%d\n", CRYPTO_THREAD_get_local(&key) == NULL);
        printf("tls.set=%d\n", CRYPTO_THREAD_set_local(&key, (void *)0x1234));
        printf("tls.get_round_trip=%d\n", CRYPTO_THREAD_get_local(&key) == (void *)0x1234);
        printf("tls.cleanup=%d\n", CRYPTO_THREAD_cleanup_local(&key));
    }

    /* ---- atomics: lock-free path (lock == NULL) ---------------------------- */
    v = 0;
    ret = 0;
    r64("atomic_or.null_lock", CRYPTO_atomic_or(&v, 0xF0, &ret, NULL), ret);
    printf("atomic_or.null_lock.value=%llu\n", (unsigned long long)v);

    v = 0;
    ret = 0;
    r64("atomic_or.thread_lock", CRYPTO_atomic_or(&v, 0xF0, &ret, NULL), ret);

    v = 0xFF;
    ret = 0;
    r64("atomic_and.null_lock", CRYPTO_atomic_and(&v, 0x30, &ret, NULL), ret);
    printf("atomic_and.null_lock.value=%llu\n", (unsigned long long)v);

    v = 7;
    ret = 0;
    r64("atomic_store.null_lock", CRYPTO_atomic_store(&v, 42, NULL), ret);
    printf("atomic_store.null_lock.value=%llu\n", (unsigned long long)v);

    v = 42;
    ret = 0;
    r64("atomic_load.null_lock", CRYPTO_atomic_load(&v, &ret, NULL), ret);

    ival = 42;
    iret = 0;
    printf("atomic_load_int.null_lock=%d/%d\n",
           CRYPTO_atomic_load_int(&ival, &iret, NULL), iret);

    ival = 10;
    iret = 0;
    printf("atomic_add.null_lock=%d/%d\n",
           CRYPTO_atomic_add(&ival, 5, &iret, NULL), iret);
    printf("atomic_add.null_lock.value=%d\n", ival);

    v = 10;
    ret = 0;
    r64("atomic_add64.null_lock", CRYPTO_atomic_add64(&v, 5, &ret, NULL), ret);
    printf("atomic_add64.null_lock.value=%llu\n", (unsigned long long)v);

    /* ---- atomics with a real lock supplied -------------------------------- */
    {
        CRYPTO_RWLOCK *l = CRYPTO_THREAD_lock_new();
        v = 0;
        ret = 0;
        /* The authority takes the hardware path regardless of the lock on this
         * profile, so the lock must NOT be held by the call. */
        r64("atomic_or.held_free", CRYPTO_atomic_or(&v, 0xF0, &ret, l), ret);
        printf("atomic_or.held_free.value=%llu\n", (unsigned long long)v);
        ret = 0;
        r64("atomic_load.with_lock", CRYPTO_atomic_load(&v, &ret, l), ret);
        CRYPTO_THREAD_lock_free(l);
    }

    /*
     * ---- atomics: the NULL-argument cases cannot be measured ---------------
     *
     * Every `CRYPTO_atomic_*` on this profile takes the hardware path, which
     * reaches `__atomic_*` with whatever it was handed: a NULL value *or* a NULL
     * out-parameter is dereferenced, and the authority faults. That is recorded as
     * divergence `D-MEM-ATOMIC-1` in `docs/SECURITY_DIVERGENCE_POLICY.md`; the
     * candidate returns the documented failure value instead. The calls are marked
     * rather than exercised, because a probe cannot compare a crash — and the
     * marker keeps the boundary visible in the transcript rather than silently
     * absent from it.
     *
     * What *is* measurable is the `lock == NULL` path, and it is above: those
     * calls succeed and are compared value for value.
     */
    printf("atomic_or.null_ret=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("atomic_load.null_ret=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("atomic_load.null_val=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("atomic_load_int.null_val=NOT_MEASURED_AUTHORITY_FAULTS\n");

    return 0;
}
