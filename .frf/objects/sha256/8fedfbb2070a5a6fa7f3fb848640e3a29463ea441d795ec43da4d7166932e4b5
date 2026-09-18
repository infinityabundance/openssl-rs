/*
 * RT-EVP-NAMES -- `names.c`'s four walkers and the two adders.
 *
 * The smallest court in this stratum and the one with the most delicate design, because
 * **most of what these six functions return is another stratum's contents.**
 *
 * `EVP_CIPHER_do_all` visits the legacy `OBJ_NAME` table, and `EVP_CIPHER_do_all`'s first act is
 * `OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL)`, which in the authority populates that
 * table with the one hundred and sixty-odd `EVP_aes_*`/`EVP_des_*`/… statics from `e_aes.c` and its
 * siblings. Those statics are **Phase 13's** by this stratum's own ledger. So a probe that printed
 * the visit count would be printing a number that says how much of Phase 13 exists, and the
 * authority's answer would be six hundred while the candidate's is three. That is not a behavioural
 * divergence and it must not be reported as one -- it is the same rule that forbids an observation
 * taken in a state the authority faults in.
 *
 * What the probe observes instead is the walk's **shape**, and every one of those observations is
 * contents-independent:
 *
 *   * **an alias row reports a NULL cipher and its target in `to`; a real row reports its cipher in
 *     `from` and a NULL `to`.** `do_all_cipher_fn` is two branches, and a transcription that passed
 *     the alias's `data` as the cipher would hand a caller a `char *` where an `EVP_CIPHER *`
 *     belongs. Both walks are driven over the whole table and only the *violation counts* are
 *     printed, so the count is zero on both sides however much of Phase 13 exists.
 *   * **the sorted walk is sorted.** The visitor checks `strcmp(previous, current) <= 0` over the
 *     whole sequence and prints one bit.
 *   * **a method this probe itself added is reachable through both walks**, which is the one
 *     contents-dependent fact the probe may state, because the entry is the probe's own.
 *   * **`EVP_add_cipher` refuses a NULL without raising**, returns 1 for a real method, and replaces
 *     rather than failing on a repeat.
 *   * **a method this probe added is answered back by name through `EVP_get_cipherbyname`**, and a
 *     name nobody publishes answers NULL with the error queue **unchanged** -- which is the
 *     `ERR_set_mark`/`ERR_pop_to_mark` pair around the fetch doing its job.
 *
 * `EVP_add_digest(NULL)` and the two walkers with a NULL visitor are **not called**: the authority
 * dereferences all three (`docs/SECURITY_DIVERGENCE_POLICY.md`). The probe prints those boundaries
 * rather than entering them. `EVP_add_digest` is driven with `EVP_md_null()`, whose `pkey_type` is
 * `NID_undef`, so the alias arm is not reachable from a C probe -- a probe cannot build an
 * `EVP_MD` and the installed headers keep the struct opaque. That arm is pinned in the crate's unit
 * tests, where the layout is visible, and this note is why it is absent here.
 *
 * Addresses are never printed. Every observation is a violation count, a bit, or a relation
 * between two pointers this probe holds.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

static void sayp(const char *key, const void *p)
{
    printf("%s=%s err=%lu\n", key, p == NULL ? "NULL" : "nonnull", ERR_peek_error());
    ERR_clear_error();
}

static void sayn(const char *key, long long v)
{
    printf("%s=%lld err=%lu\n", key, v, ERR_peek_error());
    ERR_clear_error();
}

/* ---- the cipher walk ---- */

struct cipher_seen {
    const EVP_CIPHER *wanted; /* the method this probe added, or NULL */
    int saw_wanted;
    int alias_rows;           /* cipher == NULL */
    int real_rows;            /* cipher != NULL */
    int alias_without_a_target; /* an alias row whose `to` is NULL: a violation */
    int real_with_a_target;     /* a real row whose `to` is non-NULL: a violation */
    int check_order;            /* set only for the sorted walk */
    int out_of_order;           /* the sorted walk's own check */
    const char *previous;
};

static void cipher_visitor(const EVP_CIPHER *ciph, const char *from, const char *to, void *x)
{
    struct cipher_seen *s = x;

    if (s == NULL)
        return;
    if (ciph == NULL) {
        s->alias_rows++;
        if (to == NULL)
            s->alias_without_a_target++;
    } else {
        s->real_rows++;
        if (to != NULL)
            s->real_with_a_target++;
        if (s->wanted != NULL && ciph == s->wanted)
            s->saw_wanted = 1;
    }
    /* The name a row is filed under is `from` for both kinds, so the sortedness check runs over
     * exactly the sequence the sorted walk promised to order -- and only that walk promises it.
     * `OBJ_NAME_do_all` is a hash-order walk and is *not* sorted: the first version of this probe
     * checked both and reported the unsorted walk as out of order on the authority, which is a
     * correct observation of the wrong contract. The strings are the table's own and stay alive for
     * the walk, so a pointer comparison is enough and nothing is copied. */
    if (s->check_order && from != NULL) {
        if (s->previous != NULL && strcmp(s->previous, from) > 0)
            s->out_of_order = 1;
        s->previous = from;
    }
}

static void say_cipher_walk(const char *key, const struct cipher_seen *s)
{
    printf("%s=saw_wanted:%d alias_without_a_target:%d real_with_a_target:%d out_of_order:%d "
           "err=%lu\n",
           key, s->saw_wanted, s->alias_without_a_target, s->real_with_a_target,
           s->out_of_order, ERR_peek_error());
    ERR_clear_error();
}

/* ---- the digest walk ---- */

struct digest_seen {
    const EVP_MD *wanted;
    int saw_wanted;
    int alias_rows;
    int real_rows;
    int alias_without_a_target;
    int real_with_a_target;
    int check_order;
    int out_of_order;
    const char *previous;
};

static void digest_visitor(const EVP_MD *md, const char *from, const char *to, void *x)
{
    struct digest_seen *s = x;

    if (s == NULL)
        return;
    if (md == NULL) {
        s->alias_rows++;
        if (to == NULL)
            s->alias_without_a_target++;
    } else {
        s->real_rows++;
        if (to != NULL)
            s->real_with_a_target++;
        if (s->wanted != NULL && md == s->wanted)
            s->saw_wanted = 1;
    }
    if (s->check_order && from != NULL) {
        if (s->previous != NULL && strcmp(s->previous, from) > 0)
            s->out_of_order = 1;
        s->previous = from;
    }
}

static void say_digest_walk(const char *key, const struct digest_seen *s)
{
    printf("%s=saw_wanted:%d alias_without_a_target:%d real_with_a_target:%d out_of_order:%d "
           "err=%lu\n",
           key, s->saw_wanted, s->alias_without_a_target, s->real_with_a_target,
           s->out_of_order, ERR_peek_error());
    ERR_clear_error();
}

int main(void)
{
    const EVP_CIPHER *null_cipher = EVP_enc_null();
    const EVP_MD *null_digest = EVP_md_null();
    struct cipher_seen cs;
    struct digest_seen ds;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /*
     * ---- `EVP_add_cipher` ----
     *
     * A NULL is refused **without raising**; `EVP_enc_null()`'s NID is `NID_undef`, so the two
     * insertions are under "UNDEF" and "undefined" and both succeed. Adding it twice is not an
     * error: the adder is a write and the answer is the last insertion's, so a transcription that
     * answered 0 for an existing name would be wrong in the second call and right in the first.
     */
    sayn("add_cipher.null", EVP_add_cipher(NULL));
    printf("add_cipher.null.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    sayp("add_cipher.null_method_pointer", (const void *) null_cipher);
    sayn("add_cipher.enc_null", EVP_add_cipher(null_cipher));
    sayn("add_cipher.enc_null_again", EVP_add_cipher(null_cipher));
    /* The entry the probe just filed, read back through the table rather than through the walk --
     * the two are separate readers of the same write and both are the adder's observable effect. */
    {
        const char *found = OBJ_NAME_get("UNDEF", OBJ_NAME_TYPE_CIPHER_METH);

        printf("add_cipher.registered=%d\n",
               found != NULL && found == (const char *) null_cipher ? 1 : 0);
    }

    /*
     * ---- the two lookups ----
     *
     * The one observation here that is contents-dependent is the first pair, and it is the probe's
     * **own** entry: the method it added a moment ago is answered back by name. Everything else is
     * independent of what Phase 13 has populated, and the second pair is the strongest of them --
     * a name nobody publishes answers NULL with the error queue **unchanged**, which is
     * `ERR_set_mark`/`ERR_pop_to_mark` around the fetch doing its job. A transcription that dropped
     * the mark and pop would leave the fetch's own failure on the queue, and the error a caller
     * read next would be one they never asked for.
     */
    {
        const EVP_CIPHER *by_name = EVP_get_cipherbyname("UNDEF");
        const EVP_CIPHER *missing;

        printf("get_cipherbyname.added=%d\n",
               by_name != NULL && by_name == null_cipher ? 1 : 0);
        ERR_clear_error();
        missing = EVP_get_cipherbyname("openssl-rs-no-such-cipher-at-all");
        sayp("get_cipherbyname.missing", (const void *) missing);
        printf("get_cipherbyname.missing.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
    }
    {
        const EVP_MD *by_name = EVP_get_digestbyname("UNDEF");
        const EVP_MD *missing;

        printf("get_digestbyname.added=%d\n",
               by_name != NULL && by_name == null_digest ? 1 : 0);
        ERR_clear_error();
        missing = EVP_get_digestbyname("openssl-rs-no-such-digest-at-all");
        sayp("get_digestbyname.missing", (const void *) missing);
        printf("get_digestbyname.missing.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
    }

    /*
     * ---- the two cipher walks ----
     */
    memset(&cs, 0, sizeof cs);
    cs.wanted = null_cipher;
    EVP_CIPHER_do_all(cipher_visitor, &cs);
    say_cipher_walk("cipher_do_all", &cs);

    memset(&cs, 0, sizeof cs);
    cs.wanted = null_cipher;
    cs.check_order = 1;
    EVP_CIPHER_do_all_sorted(cipher_visitor, &cs);
    say_cipher_walk("cipher_do_all_sorted", &cs);

    /*
     * ---- `EVP_add_digest` ----
     */
    sayn("add_digest.md_null", EVP_add_digest(null_digest));
    sayn("add_digest.md_null_again", EVP_add_digest(null_digest));
    {
        const char *found = OBJ_NAME_get("UNDEF", OBJ_NAME_TYPE_MD_METH);

        printf("add_digest.registered=%d\n",
               found != NULL && found == (const char *) null_digest ? 1 : 0);
    }

    /*
     * ---- the two digest walks ----
     */
    memset(&ds, 0, sizeof ds);
    ds.wanted = null_digest;
    EVP_MD_do_all(digest_visitor, &ds);
    say_digest_walk("md_do_all", &ds);

    memset(&ds, 0, sizeof ds);
    ds.wanted = null_digest;
    ds.check_order = 1;
    EVP_MD_do_all_sorted(digest_visitor, &ds);
    say_digest_walk("md_do_all_sorted", &ds);

    printf("add_digest.null=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("cipher_do_all.null_visitor=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("cipher_do_all_sorted.null_visitor=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("md_do_all.null_visitor=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("md_do_all_sorted.null_visitor=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("add_digest.pkey_alias_arm=NOT_MEASURED_NO_WAY_TO_BUILD_AN_EVP_MD_FROM_C\n");

    return 0;
}
