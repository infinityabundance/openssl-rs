/*
 * openssl-rs — RT-STACK probe.
 *
 * One program, compiled against the authority and against the candidate and
 * diffed. `STACK_OF(T)` is the collection behind most of OpenSSL's public
 * surface, and the parts that cannot be reasoned out are the ones this probe
 * concentrates on:
 *
 *   * `find`/`find_ex`/`find_all` return an INDEX and, with a comparator,
 *     search by ordering rather than by pointer identity;
 *   * the comparator is handed POINTERS TO ELEMENTS, not the elements;
 *   * on a sorted stack the search is `ossl_bsearch`, so `find_ex` answers the
 *     nearest element on a miss;
 *   * `insert` with a negative position APPENDS rather than failing;
 *   * `zero` does not clear the sorted flag, and `sort` without a comparator
 *     does not set it;
 *   * `dup`/`deep_copy` of NULL return a fresh empty stack, not NULL.
 *
 * The comparators below are written the way `safestack.h` generates them — they
 * dereference both arguments — so a candidate that passed element values instead
 * of element addresses would crash or mismatch here rather than quietly pass.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/safestack.h>
#include <openssl/stack.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_copies;
static int g_frees;
static int g_free_order[16];

static int cmp_int(const int *const *a, const int *const *b)
{
    if (**a < **b)
        return -1;
    if (**a > **b)
        return 1;
    return 0;
}

static void free_int(int *p)
{
    g_free_order[g_frees++] = *p;
    free(p);
}

static int *copy_int(const int *p)
{
    int *q = malloc(sizeof(*q));
    if (q != NULL)
        *q = *p;
    g_copies++;
    return q;
}

static int *mkint(int v)
{
    int *p = malloc(sizeof(*p));
    if (p != NULL)
        *p = v;
    return p;
}

/* A thunk in the shape `sk_TYPE_pop_free` installs: it receives the typed free
 * function and the element. */
static void *g_thunk_elems[16];
static int g_thunk_calls;

static void freefun_thunk(OPENSSL_sk_freefunc func, void *elem)
{
    g_thunk_elems[g_thunk_calls++] = elem;
    ((void (*)(void *))func)(elem);
}

static void free_void(void *p)
{
    g_free_order[g_frees++] = *(int *)p;
    free(p);
}

/* ------------------------------------------------------------------------- */

static void null_and_empty(void)
{
    OPENSSL_STACK *st = OPENSSL_sk_new_null();
    OPENSSL_STACK *dup;

    printf("null.num=%d\n", OPENSSL_sk_num(NULL));
    printf("null.value=%d\n", OPENSSL_sk_value(NULL, 0) == NULL);
    printf("null.is_sorted=%d\n", OPENSSL_sk_is_sorted(NULL));
    printf("null.pop=%d\n", OPENSSL_sk_pop(NULL) == NULL);
    printf("null.shift=%d\n", OPENSSL_sk_shift(NULL) == NULL);
    printf("null.delete=%d\n", OPENSSL_sk_delete(NULL, 0) == NULL);
    printf("null.delete_ptr=%d\n", OPENSSL_sk_delete_ptr(NULL, (void *)1) == NULL);
    printf("null.find=%d\n", OPENSSL_sk_find(NULL, (void *)1));
    printf("null.find_ex=%d\n", OPENSSL_sk_find_ex(NULL, (void *)1));
    {
        int n = 77;
        printf("null.find_all=%d\n", OPENSSL_sk_find_all(NULL, (void *)1, &n));
        printf("null.find_all_pnum_untouched=%d\n", n == 77);
    }
    printf("null.push=%d\n", OPENSSL_sk_push(NULL, (void *)1));
    printf("null.reserve=%d\n", OPENSSL_sk_reserve(NULL, 0));
    printf("null.set_thunks_is_null=%d\n", OPENSSL_sk_set_thunks(NULL, NULL) == NULL);
    OPENSSL_sk_free(NULL);
    printf("null.free_survived=1\n");
    OPENSSL_sk_pop_free(NULL, NULL);
    printf("null.pop_free_survived=1\n");
    OPENSSL_sk_zero(NULL);
    printf("null.zero_survived=1\n");

    dup = OPENSSL_sk_dup(NULL);
    printf("null.dup_nonnull=%d\n", dup != NULL);
    printf("null.dup_num=%d\n", OPENSSL_sk_num(dup));
    printf("null.dup_is_sorted=%d\n", OPENSSL_sk_is_sorted(dup));
    OPENSSL_sk_free(dup);

    dup = OPENSSL_sk_deep_copy(NULL, NULL, NULL);
    printf("null.deep_copy_nonnull=%d\n", dup != NULL);
    printf("null.deep_copy_num=%d\n", OPENSSL_sk_num(dup));
    OPENSSL_sk_free(dup);

    printf("empty.num=%d\n", OPENSSL_sk_num(st));
    printf("empty.value0=%d\n", OPENSSL_sk_value(st, 0) == NULL);
    printf("empty.value_neg=%d\n", OPENSSL_sk_value(st, -1) == NULL);
    printf("empty.find=%d\n", OPENSSL_sk_find(st, (void *)1));
    printf("empty.find_ex=%d\n", OPENSSL_sk_find_ex(st, (void *)1));
    printf("empty.pop=%d\n", OPENSSL_sk_pop(st) == NULL);
    printf("empty.shift=%d\n", OPENSSL_sk_shift(st) == NULL);
    printf("empty.sort_survived=1\n");
    OPENSSL_sk_sort(st);
    printf("empty.after_sort_is_sorted=%d\n", OPENSSL_sk_is_sorted(st));
    OPENSSL_sk_free(st);
}

static void unordered_identity(void)
{
    int a = 10, b = 20, c = 30;
    OPENSSL_STACK *st = OPENSSL_sk_new_null();

    printf("unordered.push1=%d\n", OPENSSL_sk_push(st, &a));
    printf("unordered.push2=%d\n", OPENSSL_sk_push(st, &b));
    printf("unordered.push3=%d\n", OPENSSL_sk_push(st, &c));
    printf("unordered.num=%d\n", OPENSSL_sk_num(st));
    printf("unordered.value0=%d\n", *(int *)OPENSSL_sk_value(st, 0));
    printf("unordered.value2=%d\n", *(int *)OPENSSL_sk_value(st, 2));
    printf("unordered.value3=%d\n", OPENSSL_sk_value(st, 3) == NULL);
    printf("unordered.value_neg=%d\n", OPENSSL_sk_value(st, -1) == NULL);

    /* Without a comparator, identity of the element pointer decides. An int with
     * an equal VALUE but a different address is not a match, which is what
     * distinguishes an identity search from an ordering search. */
    printf("unordered.find_b=%d\n", OPENSSL_sk_find(st, &b));
    printf("unordered.find_a=%d\n", OPENSSL_sk_find(st, &a));
    {
        int z = 10;
        printf("unordered.find_equal_value=%d\n", OPENSSL_sk_find(st, &z));
    }
    printf("unordered.find_ex_b=%d\n", OPENSSL_sk_find_ex(st, &b));
    {
        int z = 10;
        printf("unordered.find_ex_equal_value=%d\n", OPENSSL_sk_find_ex(st, &z));
    }
    printf("unordered.find_null=%d\n", OPENSSL_sk_find(st, NULL));
    {
        int n = 77;
        printf("unordered.find_all_b=%d\n", OPENSSL_sk_find_all(st, &b, &n));
        printf("unordered.find_all_pnum=%d\n", n);
        printf("unordered.find_all_a=%d\n", OPENSSL_sk_find_all(st, &a, &n));
        printf("unordered.find_all_a_pnum=%d\n", n);
        printf("unordered.find_all_nullpnum=%d\n", OPENSSL_sk_find_all(st, &b, NULL));
    }

    printf("unordered.insert_neg=%d\n", OPENSSL_sk_insert(st, &b, -1));
    printf("unordered.after_insert_neg_num=%d\n", OPENSSL_sk_num(st));
    printf("unordered.after_insert_neg_last=%d\n",
           *(int *)OPENSSL_sk_value(st, OPENSSL_sk_num(st) - 1));
    printf("unordered.insert_beyond=%d\n", OPENSSL_sk_insert(st, &a, 99));
    printf("unordered.after_insert_beyond_num=%d\n", OPENSSL_sk_num(st));
    printf("unordered.insert_at1=%d\n", OPENSSL_sk_insert(st, &c, 1));
    printf("unordered.after_insert_at1=%d,%d,%d,%d,%d\n",
           *(int *)OPENSSL_sk_value(st, 0), *(int *)OPENSSL_sk_value(st, 1),
           *(int *)OPENSSL_sk_value(st, 2), *(int *)OPENSSL_sk_value(st, 3),
           *(int *)OPENSSL_sk_value(st, 4));

    printf("unordered.set_ret=%d\n", *(int *)OPENSSL_sk_set(st, 0, &b));
    printf("unordered.set_value0=%d\n", *(int *)OPENSSL_sk_value(st, 0));
    printf("unordered.set_oob_ret=%d\n", OPENSSL_sk_set(st, 99, &b) == NULL);
    printf("unordered.set_oob_neg=%d\n", OPENSSL_sk_set(st, -1, &b) == NULL);

    printf("unordered.unshift=%d\n", OPENSSL_sk_unshift(st, &a));
    printf("unordered.after_unshift0=%d\n", *(int *)OPENSSL_sk_value(st, 0));
    printf("unordered.shift=%d\n", *(int *)OPENSSL_sk_shift(st));
    printf("unordered.pop=%d\n", *(int *)OPENSSL_sk_pop(st));
    printf("unordered.delete0=%d\n", *(int *)OPENSSL_sk_delete(st, 0));
    printf("unordered.delete_oob=%d\n", OPENSSL_sk_delete(st, 99) == NULL);
    printf("unordered.num_final=%d\n", OPENSSL_sk_num(st));

    OPENSSL_sk_free(st);
}

static void sorted_search(void)
{
    int vals[8] = {50, 10, 40, 20, 30, 20, 30, 10};
    int i;
    int probes[5] = {10, 25, 20, 50, 99};
    OPENSSL_STACK *st = OPENSSL_sk_new((OPENSSL_sk_compfunc)cmp_int);

    for (i = 0; i < 8; i++)
        (void)OPENSSL_sk_push(st, &vals[i]);

    printf("sorted.before_is_sorted=%d\n", OPENSSL_sk_is_sorted(st));
    printf("sorted.unsorted_find_20=%d\n", OPENSSL_sk_find(st, &vals[3]));
    printf("sorted.unsorted_find_ex_25=%d\n", OPENSSL_sk_find_ex(st, &probes[1]));

    OPENSSL_sk_sort(st);
    printf("sorted.after_is_sorted=%d\n", OPENSSL_sk_is_sorted(st));
    for (i = 0; i < 8; i++)
        printf("sorted.order%d=%d\n", i, *(int *)OPENSSL_sk_value(st, i));

    for (i = 0; i < 5; i++) {
        printf("sorted.find_%d=%d\n", probes[i], OPENSSL_sk_find(st, &probes[i]));
        printf("sorted.find_ex_%d=%d\n", probes[i], OPENSSL_sk_find_ex(st, &probes[i]));
    }
    for (i = 0; i < 5; i++) {
        int n = 77;
        int idx = OPENSSL_sk_find_all(st, &probes[i], &n);
        printf("sorted.find_all_%d=%d\n", probes[i], idx);
        printf("sorted.find_all_%d_pnum=%d\n", probes[i], n);
    }

    /* A NULL key with a comparator installed: `internal_find` returns -1 and
     * leaves `*pnum` alone. */
    {
        int n = 55;
        printf("sorted.find_null=%d\n", OPENSSL_sk_find(st, NULL));
        printf("sorted.find_all_null=%d\n", OPENSSL_sk_find_all(st, NULL, &n));
        printf("sorted.find_all_null_pnum_untouched=%d\n", n == 55);
    }

    /* Re-setting the comparator invalidates the sorted flag; setting the SAME
     * comparator does not. */
    {
        OPENSSL_sk_compfunc prev = OPENSSL_sk_set_cmp_func(st, (OPENSSL_sk_compfunc)cmp_int);
        printf("sorted.set_same_returns_prev=%d\n", prev == (OPENSSL_sk_compfunc)cmp_int);
        printf("sorted.set_same_keeps_sorted=%d\n", OPENSSL_sk_is_sorted(st));
    }

    /* Deleting leaves the sorted flag set (the authority does not clear it). */
    printf("sorted.delete_at0=%d\n", *(int *)OPENSSL_sk_delete(st, 0));
    printf("sorted.after_delete_is_sorted=%d\n", OPENSSL_sk_is_sorted(st));
    printf("sorted.after_delete_num=%d\n", OPENSSL_sk_num(st));

    /* `zero` empties without clearing the flag. */
    OPENSSL_sk_zero(st);
    printf("sorted.after_zero_is_sorted=%d\n", OPENSSL_sk_is_sorted(st));
    printf("sorted.after_zero_num=%d\n", OPENSSL_sk_num(st));
    printf("sorted.after_zero_push=%d\n", OPENSSL_sk_push(st, &vals[0]));
    printf("sorted.after_zero_push_is_sorted=%d\n", OPENSSL_sk_is_sorted(st));
    OPENSSL_sk_free(st);

    /* Sorting without a comparator must not mark the stack sorted. */
    st = OPENSSL_sk_new_null();
    (void)OPENSSL_sk_push(st, &vals[1]);
    (void)OPENSSL_sk_push(st, &vals[2]);
    printf("nocomp.before=%d\n", OPENSSL_sk_is_sorted(st));
    OPENSSL_sk_sort(st);
    printf("nocomp.after=%d\n", OPENSSL_sk_is_sorted(st));
    printf("nocomp.set_cmp_prev_null=%d\n",
           OPENSSL_sk_set_cmp_func(st, (OPENSSL_sk_compfunc)cmp_int) == NULL);
    OPENSSL_sk_free(st);
}

static void reserve_and_new_reserve(void)
{
    OPENSSL_STACK *st = OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)cmp_int, 8);
    printf("reserve.new_nonnull=%d\n", st != NULL);
    printf("reserve.new_num=%d\n", OPENSSL_sk_num(st));
    printf("reserve.n_zero=%d\n", OPENSSL_sk_reserve(st, 0));
    printf("reserve.n_neg=%d\n", OPENSSL_sk_reserve(st, -5));
    printf("reserve.n_positive=%d\n", OPENSSL_sk_reserve(st, 64));
    printf("reserve.n_after_num=%d\n", OPENSSL_sk_num(st));
    OPENSSL_sk_free(st);

    st = OPENSSL_sk_new_reserve(NULL, 0);
    printf("reserve.new_reserve_zero_nonnull=%d\n", st != NULL);
    printf("reserve.new_reserve_zero_is_sorted=%d\n", OPENSSL_sk_is_sorted(st));
    OPENSSL_sk_free(st);
}

static void dup_and_deep_copy(void)
{
    int a = 1, b = 2, c = 3;
    OPENSSL_STACK *src = OPENSSL_sk_new((OPENSSL_sk_compfunc)cmp_int);
    OPENSSL_STACK *dup;

    (void)OPENSSL_sk_push(src, &c);
    (void)OPENSSL_sk_push(src, &a);
    (void)OPENSSL_sk_push(src, &b);
    OPENSSL_sk_sort(src);

    dup = OPENSSL_sk_dup(src);
    printf("dup.nonnull=%d\n", dup != NULL);
    printf("dup.num=%d\n", OPENSSL_sk_num(dup));
    printf("dup.is_sorted=%d\n", OPENSSL_sk_is_sorted(dup));
    printf("dup.shares_elements=%d\n", OPENSSL_sk_value(dup, 0) == &a);
    OPENSSL_sk_free(dup);

    /* Shallow copy of an empty stack reports the same sorted flag. */
    {
        OPENSSL_STACK *empty = OPENSSL_sk_new_null();
        dup = OPENSSL_sk_dup(empty);
        printf("dup.empty_num=%d\n", OPENSSL_sk_num(dup));
        printf("dup.empty_is_sorted=%d\n", OPENSSL_sk_is_sorted(dup));
        OPENSSL_sk_free(dup);
        OPENSSL_sk_free(empty);
    }

    /* Deep copy actually copies, and calls the copy function once per element. */
    g_copies = 0;
    dup = OPENSSL_sk_deep_copy(src, (OPENSSL_sk_copyfunc)copy_int,
                               (OPENSSL_sk_freefunc)free_int);
    printf("deep.nonnull=%d\n", dup != NULL);
    printf("deep.num=%d\n", OPENSSL_sk_num(dup));
    printf("deep.copy_calls=%d\n", g_copies);
    printf("deep.distinct=%d\n", OPENSSL_sk_value(dup, 0) != &a);
    printf("deep.equal_values=%d,%d,%d\n",
           *(int *)OPENSSL_sk_value(dup, 0), *(int *)OPENSSL_sk_value(dup, 1),
           *(int *)OPENSSL_sk_value(dup, 2));
    printf("deep.is_sorted=%d\n", OPENSSL_sk_is_sorted(dup));

    g_frees = 0;
    OPENSSL_sk_pop_free(dup, (OPENSSL_sk_freefunc)free_int);
    printf("deep.free_calls=%d\n", g_frees);
    printf("deep.free_order=%d,%d,%d\n", g_free_order[0], g_free_order[1], g_free_order[2]);

    /* A deep copy of an empty source copies nothing. */
    {
        OPENSSL_STACK *empty = OPENSSL_sk_new_null();
        g_copies = 0;
        dup = OPENSSL_sk_deep_copy(empty, (OPENSSL_sk_copyfunc)copy_int,
                                   (OPENSSL_sk_freefunc)free_int);
        printf("deep.empty_num=%d\n", OPENSSL_sk_num(dup));
        printf("deep.empty_copy_calls=%d\n", g_copies);
        OPENSSL_sk_free(dup);
        OPENSSL_sk_free(empty);
    }

    OPENSSL_sk_free(src);
}

static void pop_free_and_thunks(void)
{
    OPENSSL_STACK *st = OPENSSL_sk_new_null();
    int i;

    for (i = 0; i < 4; i++)
        (void)OPENSSL_sk_push(st, mkint(i + 1));

    /* `pop_free` walks every non-NULL element in order, then frees the stack. */
    g_frees = 0;
    OPENSSL_sk_pop_free(st, (OPENSSL_sk_freefunc)free_int);
    printf("popfree.calls=%d\n", g_frees);
    printf("popfree.order=%d,%d,%d,%d\n", g_free_order[0], g_free_order[1],
           g_free_order[2], g_free_order[3]);

    /* With a thunk installed the thunk is invoked instead, receiving the typed
     * free function and the element. */
    st = OPENSSL_sk_new_null();
    for (i = 0; i < 3; i++)
        (void)OPENSSL_sk_push(st, mkint(10 + i));
    printf("thunk.set_returns_same=%d",
           OPENSSL_sk_set_thunks(st, (OPENSSL_sk_freefunc_thunk)freefun_thunk) == st);
    g_frees = 0;
    g_thunk_calls = 0;
    OPENSSL_sk_pop_free(st, (OPENSSL_sk_freefunc)free_void);
    printf("thunk.calls=%d\n", g_thunk_calls);
    printf("thunk.freed=%d\n", g_frees);
    printf("thunk.elem_was_passed=%d",
           g_thunk_elems[0] != NULL && g_thunk_elems[1] != NULL && g_thunk_elems[2] != NULL);

    /* NULL elements are skipped by `pop_free`, and a NULL element with no
     * thunk and no destructor must not be a fault. */
    st = OPENSSL_sk_new_null();
    (void)OPENSSL_sk_push(st, NULL);
    (void)OPENSSL_sk_push(st, mkint(7));
    (void)OPENSSL_sk_push(st, NULL);
    g_frees = 0;
    OPENSSL_sk_pop_free(st, (OPENSSL_sk_freefunc)free_int);
    printf("popfree.null_skipped=%d\n", g_frees == 1);
}

static void delete_ptr_and_zero(void)
{
    int a = 1, b = 2;
    OPENSSL_STACK *st = OPENSSL_sk_new_null();

    (void)OPENSSL_sk_push(st, &a);
    (void)OPENSSL_sk_push(st, &b);
    (void)OPENSSL_sk_push(st, &a);
    printf("ptr.delete_returns=%d\n", *(int *)OPENSSL_sk_delete_ptr(st, &a));
    printf("ptr.num_after=%d\n", OPENSSL_sk_num(st));
    printf("ptr.value0=%d\n", *(int *)OPENSSL_sk_value(st, 0));
    printf("ptr.delete_b=%d\n", *(int *)OPENSSL_sk_delete_ptr(st, &b));
    printf("ptr.num_after_b=%d\n", OPENSSL_sk_num(st));
    printf("ptr.delete_second_a=%d\n", *(int *)OPENSSL_sk_delete_ptr(st, &a));
    printf("ptr.num_after_second_a=%d\n", OPENSSL_sk_num(st));
    printf("ptr.delete_missing=%d\n", OPENSSL_sk_delete_ptr(st, &a) == NULL);

    /* `zero` on an unordered stack: the count empties and the sorted flag was
     * already clear, so it stays clear. */
    (void)OPENSSL_sk_push(st, &a);
    (void)OPENSSL_sk_push(st, &b);
    printf("zero.before_num=%d\n", OPENSSL_sk_num(st));
    OPENSSL_sk_zero(st);
    printf("zero.after_num=%d\n", OPENSSL_sk_num(st));
    printf("zero.after_is_sorted=%d\n", OPENSSL_sk_is_sorted(st));
    printf("zero.after_value0=%d\n", OPENSSL_sk_value(st, 0) == NULL);
    printf("zero.reuse_push=%d\n", OPENSSL_sk_push(st, &a));
    OPENSSL_sk_free(st);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("probe.rt-stack=1\n");

    null_and_empty();
    unordered_identity();
    sorted_search();
    reserve_and_new_reserve();
    dup_and_deep_copy();
    pop_free_and_thunks();
    delete_ptr_and_zero();

    printf("done=1\n");
    return 0;
}
