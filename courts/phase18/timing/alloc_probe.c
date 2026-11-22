/*
 * LD_PRELOAD allocation probe for the BN ladder measurements and the PFP-0
 * cross-subject population.
 *
 * Counts every allocation entry point a workload can reach through libc
 * (`malloc`, `calloc`, `realloc`, `aligned_alloc`, `posix_memalign`, `memalign`)
 * and `free` calls.  `allocprobe_alloc_calls()` is the unified count used by
 * PFP-0 for both subjects; `allocprobe_mallocs()` keeps the older
 * malloc/calloc/realloc meaning so a new measurement can be compared with the
 * earlier candidate-only rows without pretending the two counters are equal.
 *
 * It can also force the Nth allocation after allocprobe_fail_after() to return
 * NULL so the caller's allocation-failure behaviour is observed rather than
 * assumed.
 *
 * The bootstrap arena exists because dlsym may itself allocate while the real
 * symbols are being resolved.  Anything served from the arena is recognised by
 * address and freed as a no-op.
 *
 * Build:
 *   cc -O2 -fPIC -shared alloc_probe.c -ldl -o /tmp/alloc_probe.so
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *(*real_malloc)(size_t);
static void *(*real_calloc)(size_t, size_t);
static void *(*real_realloc)(void *, size_t);
static void (*real_free)(void *);
static void *(*real_aligned_alloc)(size_t, size_t);
static int (*real_posix_memalign)(void **, size_t, size_t);
static void *(*real_memalign)(size_t, size_t);

static unsigned long g_malloc_class;
static unsigned long g_alloc_calls;
static unsigned long g_frees;
static unsigned long g_fail_countdown;

/* Bootstrap arena for allocations made while dlsym resolves the real symbols. */
static _Alignas(16) unsigned char arena[65536];
static size_t arena_used;
static int resolving;

static int from_arena(const void *p)
{
    const unsigned char *b = p;

    return b >= arena && b < arena + sizeof arena;
}

static void *arena_alloc(size_t n)
{
    size_t aligned = (n + 15u) & ~(size_t)15u;

    if (aligned > sizeof arena - arena_used)
        return NULL;
    void *p = arena + arena_used;

    arena_used += aligned;
    return p;
}

static void resolve(void)
{
    if (real_malloc != NULL)
        return;
    resolving = 1;
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_free = dlsym(RTLD_NEXT, "free");
    real_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");
    real_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
    real_memalign = dlsym(RTLD_NEXT, "memalign");
    resolving = 0;
}

static int should_fail(void)
{
    if (g_fail_countdown == 0)
        return 0;
    if (--g_fail_countdown == 0)
        return 1;
    return 0;
}

void allocprobe_reset(void)
{
    g_malloc_class = 0;
    g_alloc_calls = 0;
    g_frees = 0;
}

void allocprobe_fail_after(unsigned long n)
{
    g_fail_countdown = n;
}

unsigned long allocprobe_mallocs(void)
{
    return g_malloc_class;
}

/* PFP-0 unified count: every allocation entry point this probe observes. */
unsigned long allocprobe_alloc_calls(void)
{
    return g_alloc_calls;
}

unsigned long allocprobe_frees(void)
{
    return g_frees;
}

void *malloc(size_t n)
{
    if (real_malloc == NULL && !resolving)
        resolve();
    if (resolving || real_malloc == NULL) {
        resolving = 1;
        void *p = arena_alloc(n);
        resolving = 0;
        return p;
    }
    g_malloc_class++;
    g_alloc_calls++;
    if (should_fail())
        return NULL;
    return real_malloc(n);
}

void *calloc(size_t a, size_t b)
{
    if (real_malloc == NULL && !resolving)
        resolve();
    if (resolving || real_calloc == NULL) {
        size_t n;

        if (__builtin_mul_overflow(a, b, &n))
            return NULL;
        resolving = 1;
        void *p = arena_alloc(n);
        resolving = 0;
        if (p != NULL)
            memset(p, 0, n);
        return p;
    }
    g_malloc_class++;
    g_alloc_calls++;
    if (should_fail())
        return NULL;
    return real_calloc(a, b);
}

void *realloc(void *p, size_t n)
{
    if (real_malloc == NULL && !resolving)
        resolve();
    if (resolving || real_realloc == NULL) {
        void *q = arena_alloc(n);

        if (p != NULL && q != NULL && !from_arena(p))
            memcpy(q, p, n);
        return q;
    }
    g_malloc_class++;
    g_alloc_calls++;
    if (should_fail())
        return NULL;
    return real_realloc(p, n);
}

void *aligned_alloc(size_t alignment, size_t n)
{
    if (real_malloc == NULL && !resolving)
        resolve();
    if (resolving || real_aligned_alloc == NULL)
        return NULL;
    g_alloc_calls++;
    if (should_fail())
        return NULL;
    return real_aligned_alloc(alignment, n);
}

int posix_memalign(void **memptr, size_t alignment, size_t n)
{
    if (real_malloc == NULL && !resolving)
        resolve();
    if (resolving || real_posix_memalign == NULL)
        return ENOMEM;
    g_alloc_calls++;
    if (should_fail())
        return ENOMEM;
    return real_posix_memalign(memptr, alignment, n);
}

void *memalign(size_t alignment, size_t n)
{
    if (real_malloc == NULL && !resolving)
        resolve();
    if (resolving || real_memalign == NULL)
        return NULL;
    g_alloc_calls++;
    if (should_fail())
        return NULL;
    return real_memalign(alignment, n);
}

void free(void *p)
{
    if (p == NULL || from_arena(p))
        return;
    if (real_malloc == NULL && !resolving)
        resolve();
    if (resolving || real_free == NULL)
        return;
    g_frees++;
    real_free(p);
}
