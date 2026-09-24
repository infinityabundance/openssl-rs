/*
 * oracle-legacy-sha -- what `EVP_sha1()` is and what `EVP_DigestInit_ex` does with it.
 *
 * Why this exists
 * ---------------
 * `crypto/evp/legacy_sha.c:100` is `const EVP_MD *EVP_sha1(void) { return &sha1_md; }`, and
 * `sha1_md`'s legacy callback table is `LEGACY_EVP_MD_METH_TABLE(sha1_init, sha1_update,
 * sha1_final, sha1_int_ctrl, SHA_CBLOCK)`, which `legacy_meth.h:38-39` expands to
 * `init, update, final, NULL, NULL, blksz, 0, ctrl`. Read against `struct evp_md_st`
 * (`include/crypto/evp.h:258-295`), whose legacy fields are in order `init`, `update`, `final`,
 * `copy`, `cleanup`, `block_size`, `ctx_size`, `md_ctrl`, that puts `SHA_CBLOCK` in `block_size`
 * and **zero in `ctx_size`**.
 *
 * The crate must transcribe that object, so it has to know what the zero means. It matters because
 * `evp_md_init_internal` (`crypto/evp/digest.c:342`) sets `ctx->update` and allocates `ctx->md_data`
 * only `if (!(ctx->flags & EVP_MD_CTX_FLAG_NO_INIT) && type->ctx_size)`, and
 * `EVP_MD_CTX_get0_md_data` (`evp_lib.c:1087`) is a bare `return ctx->md_data;`. A zero `ctx_size`
 * therefore predicts `ctx->update == NULL` and `ctx->md_data == NULL`, and `EVP_DigestUpdate`'s
 * `legacy:` arm (`digest.c:431`) predicts `return 0`.
 *
 * **The prediction is right and the object is never used to digest anything.** D290 resolved this
 * with one line D289 had not read: `evp_md_init_internal` (`crypto/evp/digest.c:258-280`) checks
 * `type->prov == NULL` and, for such a method, **fetches the provider implementation by
 * `OBJ_nid2sn(type->type)` and rebinds `type` to it** before `ctx->digest = type`. So a legacy
 * `EVP_MD` is a carrier whose callbacks an ENGINE may use and whose digest path the library
 * replaces. Every fact below follows from that, including the one that looked impossible:
 * `SHA1_Init` is called with a non-NULL argument because the **provider** method's own `sha1_init`
 * calls it, and this interposer cannot tell the two callers apart. That ambiguity is the lesson:
 * measuring a symbol does not measure which caller reached it.
 *
 * The measurements, in the order the program makes them
 * -----------------------------------------------------
 *   1. the fields of the object `EVP_sha1()` returns, read off the pointer through a local replica
 *      of `struct evp_md_st` whose offsets are printed so a layout error is visible:
 *      `type` 64, `pkey_type` 65, `md_size` 20, `flags` 8, `origin` 1, `block_size` **64**,
 *      `ctx_size` **0**, `copy`/`cleanup` NULL, `init`/`update`/`final`/`md_ctrl` non-NULL;
 *   2. `ctx->md_data` is NULL **before** `EVP_DigestInit_ex` and still NULL **after** it, which
 *      returned 1;
 *   3. `EVP_MD_CTX_get0_md(ctx)` after the init is **the same pointer** `EVP_sha1()` returned, and
 *      not a fetched replacement -- `EVP_MD_fetch(NULL, "SHA1", NULL)` answers a different address,
 *      so no provider method was substituted;
 *   4. and yet `EVP_DigestUpdate` and `EVP_DigestFinal_ex` both answer 1 and the digest is the
 *      published SHA-1 of `"abc"`, `a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d`, with an empty
 *      error queue.
 *
 * Facts 2 and 4 cannot both hold if `EVP_MD_CTX_get0_md_data` is the only way to the state, and
 * facts 3 and 1 cannot both hold if the digest is a provider method. The next probe is therefore
 * not another reading: it is a link against the pinned **static** archive
 * (`forensics/authorities/build/openssl-3.6.4-production/libcrypto.a`, which
 * `oracle-polyval.c` and `oracle-chacha20-poly1305-hw.c` already link) so that `sha1_md`'s address
 * and `ctx->md_data`'s write can be watched directly, or a debugger breakpoint on `SHA1_Init`.
 *
 * Build (inside the court; `$B` is the installed prefix)
 * -----------------------------------------------------
 *   clang -std=c11 -O1 -DNDEBUG -I $B/include -o /tmp/oracle-legacy-sha \
 *       courts/layout/oracle-legacy-sha.c -L $B/lib -lcrypto -Wl,-rpath,$B/lib
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdio.h>

/* A local replica of `struct evp_md_st` (`include/crypto/evp.h:258-295`): same fields, same order,
 * same types, so the compiler lays it out identically and the fields can be read off the pointer.
 * The offsets are printed first, so a replica that stopped matching the authority would be visible
 * rather than silent. */
struct md_st {
    int type;
    int pkey_type;
    int md_size;
    unsigned long flags;
    int origin;
    int (*init)(void *);
    int (*update)(void *, const void *, size_t);
    int (*final)(void *, unsigned char *);
    int (*copy)(void *, const void *);
    int (*cleanup)(void *);
    int block_size;
    int ctx_size;
    int (*md_ctrl)(void *, int, int, void *);
    int name_id;
    char *type_name;
    const char *description;
    void *prov;
    int refcnt;
};

int main(void)
{
    const struct md_st *m = (const struct md_st *)EVP_sha1();
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    const EVP_MD *used;
    unsigned char md[64];
    unsigned int n = 0;
    unsigned long e;
    unsigned int i;

    /* (1) the offsets, then the fields. */
    printf("off.block_size=%zu off.ctx_size=%zu off.name_id=%zu\n",
        offsetof(struct md_st, block_size), offsetof(struct md_st, ctx_size),
        offsetof(struct md_st, name_id));
    printf("f.type=%d f.pkey_type=%d f.md_size=%d\n", m->type, m->pkey_type, m->md_size);
    printf("f.flags=%lu f.origin=%d\n", m->flags, m->origin);
    printf("f.block_size=%d f.ctx_size=%d\n", m->block_size, m->ctx_size);
    printf("f.init=%d f.update=%d f.final=%d\n",
        m->init != NULL, m->update != NULL, m->final != NULL);
    printf("f.copy=%d f.cleanup=%d f.md_ctrl=%d\n",
        m->copy != NULL, m->cleanup != NULL, m->md_ctrl != NULL);
    printf("f.name_id=%d f.type_name=%d f.prov=%d\n",
        m->name_id, m->type_name != NULL, m->prov != NULL);

    /* (2) `md_data` on both sides of the init. */
    printf("before.md_data_is_null=%d\n", EVP_MD_CTX_get0_md_data(c) == NULL);
    printf("init_ok=%d\n", EVP_DigestInit_ex(c, EVP_sha1(), NULL));
    printf("after.md_data_is_null=%d\n", EVP_MD_CTX_get0_md_data(c) == NULL);

    /* (3) which method the context ended up holding. */
    used = EVP_MD_CTX_get0_md(c);
    printf("used.same_pointer=%d\n", used == EVP_sha1());
    printf("used.type=%d used.origin=%d used.size=%d\n",
        ((const struct md_st *)used)->type, ((const struct md_st *)used)->origin,
        EVP_MD_get_size(used));
    printf("fetch.is_the_same_object=%d\n", EVP_MD_fetch(NULL, "SHA1", NULL) == used);

    /* (4) and the digest. */
    printf("update_ok=%d\n", EVP_DigestUpdate(c, "abc", 3));
    printf("final_ok=%d\n", EVP_DigestFinal_ex(c, md, &n));
    printf("outlen=%u\n", n);
    for (i = 0; i < n && i < 20; i++)
        printf("md.%02u=%02x\n", i, md[i]);
    while ((e = ERR_get_error()) != 0)
        printf("err=%lu\n", e);
    EVP_MD_CTX_free(c);
    return 0;
}
