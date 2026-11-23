/*
 * pop_free_order_probe.c — destructive-order and scaling probe for
 * OPENSSL_sk_pop_free.
 *
 * One process loads exactly one libcrypto DSO (pinned authority or the
 * candidate) with RTLD_LOCAL and resolves the stack entry points through that
 * handle, so the two implementations are never interposed on each other.
 *
 * Modes:
 *
 *   order pop_free   the public operation under test
 *   order pop        end-popping loop: the rejected reversal, linear time
 *   order shift      front-removal loop: the rejected O(n^2) shape
 *   time  <mode> <n> <reps>
 *                    wall time of the destroy path only; pushes are outside
 *                    the timed region
 *
 * Output is stable text so a transcript can be compared line by line.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct stack_st OPENSSL_STACK;
typedef void (*freefunc_t)(void *);

struct api {
    void *handle;
    OPENSSL_STACK *(*OPENSSL_sk_new_null)(void);
    int (*OPENSSL_sk_push)(OPENSSL_STACK *, const void *);
    void (*OPENSSL_sk_pop_free)(OPENSSL_STACK *, freefunc_t);
    int (*OPENSSL_sk_num)(const OPENSSL_STACK *);
    void *(*OPENSSL_sk_shift)(OPENSSL_STACK *);
    void *(*OPENSSL_sk_pop)(OPENSSL_STACK *);
    void (*OPENSSL_sk_free)(OPENSSL_STACK *);
};

static volatile unsigned long sink;

static void noop_free(void *p)
{
    (void)p;
    sink++;
}

static int order_ids[64];
static int order_log[64];
static int order_count;

static void log_free(void *p)
{
    if (order_count < 64)
        order_log[order_count++] = *(const int *)p;
}

static int load_api(const char *path, struct api *api)
{
    memset(api, 0, sizeof(*api));
    api->handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (api->handle == NULL) {
        fprintf(stderr, "dlopen %s: %s\n", path, dlerror());
        return 1;
    }
#define RESOLVE(field)                                                       \
    do {                                                                     \
        *(void **)(&api->field) = dlsym(api->handle, #field);                \
        if (api->field == NULL) {                                           \
            fprintf(stderr, "dlsym %s: %s\n", #field, dlerror());           \
            return 1;                                                        \
        }                                                                    \
    } while (0)
    RESOLVE(OPENSSL_sk_new_null);
    RESOLVE(OPENSSL_sk_push);
    RESOLVE(OPENSSL_sk_pop_free);
    RESOLVE(OPENSSL_sk_num);
    RESOLVE(OPENSSL_sk_shift);
    RESOLVE(OPENSSL_sk_pop);
    RESOLVE(OPENSSL_sk_free);
#undef RESOLVE
    return 0;
}

static double now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(2);
    }
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static OPENSSL_STACK *make_stack(struct api *api, int n)
{
    int i;

    OPENSSL_STACK *st = api->OPENSSL_sk_new_null();
    if (st == NULL) {
        fprintf(stderr, "OPENSSL_sk_new_null failed\n");
        exit(2);
    }
    for (i = 0; i < n; i++) {
        if (api->OPENSSL_sk_push(st, (const void *)(uintptr_t)(i + 1)) != i + 1) {
            fprintf(stderr, "OPENSSL_sk_push failed at %d\n", i);
            exit(2);
        }
    }
    return st;
}

static void destroy(struct api *api, OPENSSL_STACK *st, const char *mode,
                    freefunc_t callback)
{
    if (strcmp(mode, "pop_free") == 0) {
        api->OPENSSL_sk_pop_free(st, callback);
        return;
    }
    if (strcmp(mode, "pop") == 0) {
        void *p;
        while ((p = api->OPENSSL_sk_pop(st)) != NULL)
            callback(p);
        api->OPENSSL_sk_free(st);
        return;
    }
    if (strcmp(mode, "shift") == 0) {
        void *p;
        while ((p = api->OPENSSL_sk_shift(st)) != NULL)
            callback(p);
        api->OPENSSL_sk_free(st);
        return;
    }
    fprintf(stderr, "unknown mode %s\n", mode);
    exit(2);
}

static int run_order(struct api *api, const char *mode)
{
    const int n = 8;
    int i;

    OPENSSL_STACK *st = api->OPENSSL_sk_new_null();
    if (st == NULL) {
        fprintf(stderr, "OPENSSL_sk_new_null failed\n");
        return 1;
    }
    for (i = 0; i < n; i++) {
        order_ids[i] = i;
        if (api->OPENSSL_sk_push(st, &order_ids[i]) != i + 1) {
            fprintf(stderr, "OPENSSL_sk_push failed at %d\n", i);
            return 1;
        }
    }
    order_count = 0;
    destroy(api, st, mode, log_free);

    printf("ORDER %s", mode);
    for (i = 0; i < order_count; i++)
        printf("%s%d", i == 0 ? " " : ",", order_log[i]);
    printf("\n");
    return 0;
}

static int run_time(struct api *api, const char *mode, int n, int reps)
{
    int r;

    /* Warm up once, outside the reported samples. */
    {
        OPENSSL_STACK *st = make_stack(api, n);
        destroy(api, st, mode, noop_free);
    }
    for (r = 0; r < reps; r++) {
        OPENSSL_STACK *st = make_stack(api, n);
        double t0 = now_ns();
        destroy(api, st, mode, noop_free);
        double t1 = now_ns();
        printf("TIME %s %d %d %.0f\n", mode, n, r, t1 - t0);
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct api api;

    if (argc < 4) {
        fprintf(stderr,
                "usage: %s <libcrypto.so.3> order <pop_free|pop|shift>\n"
                "       %s <libcrypto.so.3> time <pop_free|pop|shift> <n> <reps>\n",
                argv[0], argv[0]);
        return 2;
    }
    if (load_api(argv[1], &api) != 0)
        return 2;

    if (strcmp(argv[2], "order") == 0)
        return run_order(&api, argv[3]);

    if (strcmp(argv[2], "time") == 0) {
        if (argc != 6) {
            fprintf(stderr, "time needs <mode> <n> <reps>\n");
            return 2;
        }
        return run_time(&api, argv[3], atoi(argv[4]), atoi(argv[5]));
    }

    fprintf(stderr, "unknown command %s\n", argv[2]);
    return 2;
}
