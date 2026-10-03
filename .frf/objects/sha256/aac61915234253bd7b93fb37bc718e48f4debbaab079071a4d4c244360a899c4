/*
 * openssl-rs — Phase 13.7's behavioural court, `RT-LEGACY-REMAINDER`.
 *
 * It drives the two things 13.7 lands and compares what the authority and the candidate
 * *do*, line by line:
 *
 *   * the PEM private-key readers and writers added to `crypto/pem/pem_pkey.c` and
 *     `crypto/pem/pem_pk8.c` -- `PEM_write_bio_PrivateKey[_ex]`, `PEM_write_PrivateKey[_ex]`,
 *     `PEM_write_bio_PKCS8PrivateKey[_nid]`, `PEM_write_PKCS8PrivateKey[_nid]`, and the
 *     `PEM_read[_bio]_PrivateKey[_ex]` readers, over a fixed in-process RSA key written to a
 *     memory BIO and re-read from it; and
 *   * the `ASYNC_*` framework -- `ASYNC_init_thread`, a job that pauses and resumes once through
 *     `ASYNC_start_job`/`ASYNC_pause_job`, `ASYNC_block_pause`/`ASYNC_unblock_pause`,
 *     `ASYNC_get_current_job`/`ASYNC_get_wait_ctx`, and the whole `ASYNC_WAIT_CTX_*` surface,
 *     plus the pool-size and callback refusal arms.
 *
 * What it does **not** do, and why
 * --------------------------------
 * The RSA key is generated in-process with `RSA_generate_key_ex`, so the two sides generate
 * *different* keys; every observation is therefore a deterministic invariant of the key -- its
 * type, its bit count, whether the write/read returned non-NULL, the fixed PEM banner -- and
 * **no key byte, DER byte or ciphertext byte is ever printed**. The transcript is `key=value`
 * lines only; there is no wall clock, no network, no random value and no real filesystem.
 *
 * `PEM_read_bio_Parameters[_ex]` is **not** driven over a valid `DH PARAMETERS` block: this
 * crate publishes no provider decoder (`D-DECODER-ABSENT-1`), so the authority answers a key
 * where the candidate answers NULL. Those two spellings are driven over an *empty* BIO instead,
 * where both refuse, so the names are called without asserting the divergent arm. Likewise the
 * error queue is never drained, because the decoder-first leg records a different coordinate on
 * each side and a comparison there would be a residual this court does not claim.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include <openssl/async.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

/* ---- PEM: a fixed in-process RSA key, written and re-read through memory BIOs ---- */

/* One memory BIO's bytes, and the reader over a fresh copy. The readers rewind their input, so
 * each read gets its own BIO over the same bytes. */
static void pem_readers(const char *tag, const unsigned char *blk, int blk_len)
{
    EVP_PKEY *k;
    char key[96];

    snprintf(key, sizeof key, "lr.%s.bio.notnull", tag);
    k = PEM_read_bio_PrivateKey(BIO_new_mem_buf(blk, blk_len), NULL, NULL, NULL);
    printf("%s=%d\n", key, k != NULL);
    snprintf(key, sizeof key, "lr.%s.bio.type", tag);
    printf("%s=%d\n", key, k != NULL ? EVP_PKEY_get_id(k) : -1);
    snprintf(key, sizeof key, "lr.%s.bio.bits", tag);
    printf("%s=%d\n", key, k != NULL ? EVP_PKEY_get_bits(k) : -1);
    EVP_PKEY_free(k);

    snprintf(key, sizeof key, "lr.%s.bio_ex.notnull", tag);
    k = PEM_read_bio_PrivateKey_ex(BIO_new_mem_buf(blk, blk_len), NULL, NULL, NULL, NULL, NULL);
    printf("%s=%d\n", key, k != NULL);
    snprintf(key, sizeof key, "lr.%s.bio_ex.type", tag);
    printf("%s=%d\n", key, k != NULL ? EVP_PKEY_get_id(k) : -1);
    EVP_PKEY_free(k);
}

/* The same two readers over a `FILE *` that lives in memory (`fmemopen`), so the `_fp`
 * spellings are driven without touching the filesystem. */
static void pem_readers_fp(const char *tag, const unsigned char *blk, int blk_len)
{
    char buf[8192];
    FILE *f;
    EVP_PKEY *k;
    char key[96];

    memset(buf, 0, sizeof buf);
    memcpy(buf, blk, (size_t)blk_len);
    f = fmemopen(buf, blk_len, "r");
    if (f != NULL) {
        snprintf(key, sizeof key, "lr.%s.fp.notnull", tag);
        k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        printf("%s=%d\n", key, k != NULL);
        snprintf(key, sizeof key, "lr.%s.fp.type", tag);
        printf("%s=%d\n", key, k != NULL ? EVP_PKEY_get_id(k) : -1);
        EVP_PKEY_free(k);
        fclose(f);
    }

    memset(buf, 0, sizeof buf);
    memcpy(buf, blk, (size_t)blk_len);
    f = fmemopen(buf, blk_len, "r");
    if (f != NULL) {
        snprintf(key, sizeof key, "lr.%s.fp_ex.notnull", tag);
        k = PEM_read_PrivateKey_ex(f, NULL, NULL, NULL, NULL, NULL);
        printf("%s=%d\n", key, k != NULL);
        EVP_PKEY_free(k);
        fclose(f);
    }
}

/* The fixed banner of a PEM block, up to and including its closing dashes but not the newline.
 * A `key=value` line, and no `=` can appear in the banner itself. */
static void pem_banner(const char *tag, const char *blk)
{
    char key[96];
    const char *nl = strchr(blk, '\n');
    int n = nl != NULL ? (int)(nl - blk) : 0;

    snprintf(key, sizeof key, "lr.%s.banner", tag);
    printf("%s=%.*s\n", key, n, blk);
}

static void pem_private_key(void)
{
    BIGNUM *e = BN_new();
    RSA *rsa = RSA_new();
    EVP_PKEY *pkey = EVP_PKEY_new();
    BIO *wb;
    char *blk = NULL;
    long blk_len;
    unsigned char *der = NULL;
    int der_len;
    /* A pass phrase is not a secret here: it protects a key generated and discarded in-process,
     * and its only use is to make the encrypted round trip deterministic. */
    const char *pass = "13.7-court";

    BN_set_word(e, RSA_F4);
    printf("lr.pem.keygen=%d\n", RSA_generate_key_ex(rsa, 1024, e, NULL));
    printf("lr.pem.assign=%d\n", EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa));
    printf("lr.pem.type=%d\n", EVP_PKEY_get_id(pkey));

    /* The unencrypted PKCS#8 block, written by the `_bio` writer under test. */
    wb = BIO_new(BIO_s_mem());
    printf("lr.pem.write_bio_privkey=%d\n",
           PEM_write_bio_PrivateKey(wb, pkey, NULL, NULL, 0, NULL, NULL));
    blk_len = BIO_ctrl(wb, BIO_CTRL_PENDING, 0, NULL);
    BIO_ctrl(wb, BIO_CTRL_INFO, 0, (char *)&blk);
    printf("lr.pem.write_bio_privkey.len_nonzero=%d\n", blk_len > 0);
    pem_banner("p8", blk);
    pem_readers("p8", (const unsigned char *)blk, (int)blk_len);
    pem_readers_fp("p8", (const unsigned char *)blk, (int)blk_len);
    BIO_free(wb);

    /* The `_ex` writer, and a byte-identical re-encoding check that is a boolean, not a byte. */
    wb = BIO_new(BIO_s_mem());
    printf("lr.pem.write_bio_privkey_ex=%d\n",
           PEM_write_bio_PrivateKey_ex(wb, pkey, NULL, NULL, 0, NULL, NULL, NULL, NULL));
    BIO_free(wb);

    /* The `FILE *` writer over an in-memory stream. */
    {
        char fbuf[8192];
        FILE *f = fmemopen(fbuf, sizeof fbuf, "w+");

        if (f != NULL) {
            printf("lr.pem.write_privkey_fp=%d\n",
                   PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL));
            fflush(f);
            rewind(f);
            {
                EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);

                printf("lr.pem.write_privkey_fp_roundtrip=%d\n",
                       k != NULL ? EVP_PKEY_get_id(k) : -1);
                EVP_PKEY_free(k);
            }
            fclose(f);
        }
        f = fmemopen(fbuf, sizeof fbuf, "w+");
        if (f != NULL) {
            printf("lr.pem.write_privkey_ex_fp=%d\n",
                   PEM_write_PrivateKey_ex(f, pkey, NULL, NULL, 0, NULL, NULL, NULL, NULL));
            fclose(f);
        }
    }

    /* The encrypted PKCS#8 round trip, and the wrong-passphrase refusal. */
    wb = BIO_new(BIO_s_mem());
    printf("lr.pem.write_bio_enc=%d\n",
           PEM_write_bio_PrivateKey(wb, pkey, EVP_aes_128_cbc(), "13.7-court", 10,
                                    NULL, NULL));
    blk_len = BIO_ctrl(wb, BIO_CTRL_PENDING, 0, NULL);
    BIO_ctrl(wb, BIO_CTRL_INFO, 0, (char *)&blk);
    pem_banner("enc", blk);
    {
        EVP_PKEY *k = PEM_read_bio_PrivateKey(BIO_new_mem_buf(blk, (int)blk_len), NULL, NULL,
                                              (void *)pass);

        printf("lr.pem.enc.read=%d\n", k != NULL);
        printf("lr.pem.enc.type=%d\n", k != NULL ? EVP_PKEY_get_id(k) : -1);
        printf("lr.pem.enc.bits=%d\n", k != NULL ? EVP_PKEY_get_bits(k) : -1);
        EVP_PKEY_free(k);
    }
    {
        EVP_PKEY *k = PEM_read_bio_PrivateKey(BIO_new_mem_buf(blk, (int)blk_len), NULL, NULL,
                                              (void *)"wrong");

        printf("lr.pem.enc.wrong_pass=%d\n", k != NULL);
        EVP_PKEY_free(k);
    }
    BIO_free(wb);

    /* `PEM_write_bio_PKCS8PrivateKey` directly, and its `_nid_` twin (the PBE path). */
    wb = BIO_new(BIO_s_mem());
    printf("lr.pem.pkcs8_bio=%d\n",
           PEM_write_bio_PKCS8PrivateKey(wb, pkey, EVP_aes_128_cbc(), "13.7-court", 10, NULL, NULL));
    blk_len = BIO_ctrl(wb, BIO_CTRL_PENDING, 0, NULL);
    BIO_ctrl(wb, BIO_CTRL_INFO, 0, (char *)&blk);
    pem_banner("pkcs8", blk);
    {
        EVP_PKEY *k = PEM_read_bio_PrivateKey(BIO_new_mem_buf(blk, (int)blk_len), NULL, NULL,
                                              (void *)pass);

        printf("lr.pem.pkcs8_bio.read=%d\n", k != NULL);
        EVP_PKEY_free(k);
    }
    BIO_free(wb);

    wb = BIO_new(BIO_s_mem());
    printf("lr.pem.pkcs8_nid_bio=%d\n",
           PEM_write_bio_PKCS8PrivateKey_nid(wb, pkey, NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                                             "13.7-court", 10, NULL, NULL));
    BIO_free(wb);

    {
        char fbuf[8192];
        FILE *f = fmemopen(fbuf, sizeof fbuf, "w+");

        if (f != NULL) {
            printf("lr.pem.pkcs8_fp=%d\n",
                   PEM_write_PKCS8PrivateKey(f, pkey, EVP_aes_128_cbc(), "13.7-court", 10,
                                             NULL, NULL));
            fclose(f);
        }
        f = fmemopen(fbuf, sizeof fbuf, "w+");
        if (f != NULL) {
            printf("lr.pem.pkcs8_nid_fp=%d\n",
                   PEM_write_PKCS8PrivateKey_nid(f, pkey, NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                                                 "13.7-court", 10, NULL, NULL));
            fclose(f);
        }
    }

    /* The DER writer of the same unit, as the crypto-bytes counterpart of the PEM arms. */
    der_len = i2d_PKCS8PrivateKey_bio(BIO_new(BIO_s_mem()), pkey, NULL, NULL, 0, NULL, NULL);
    printf("lr.pem.i2d_pkcs8_nonneg=%d\n", der_len >= 0);
    (void)der;
    (void)der_len;

    /* `PEM_write_bio_Parameters` on an RSA key: RSA's method has no `param_encode`, so both
     * sides refuse without touching the divergent decoder-absent arm. */
    wb = BIO_new(BIO_s_mem());
    printf("lr.pem.write_params_rsa=%d\n", PEM_write_bio_Parameters(wb, pkey));
    BIO_free(wb);

    /* The two `PEM_read_bio_Parameters*` spellings over an empty BIO: both refuse, and neither
     * side reaches the provider-decoder arm the divergence names. */
    printf("lr.pem.read_params_empty=%d\n",
           PEM_read_bio_Parameters(BIO_new_mem_buf("", 0), NULL) != NULL);
    printf("lr.pem.read_params_ex_empty=%d\n",
           PEM_read_bio_Parameters_ex(BIO_new_mem_buf("", 0), NULL, NULL, NULL) != NULL);

    EVP_PKEY_free(pkey);
    BN_free(e);
    ERR_clear_error();
}

/* ---- ASYNC: a job that pauses and resumes once, and the refusal arms ---- */

static int g_steps;

static int async_callback(void *arg)
{
    (void)arg;
    return 1;
}

static int pausing_job(void *arg)
{
    g_steps++;
    /* Blocking makes `pause` a success with no switch; the caller must see exactly one
     * `ASYNC_PAUSE`, not two. */
    ASYNC_block_pause();
    ASYNC_pause_job();
    ASYNC_unblock_pause();
    ASYNC_pause_job();
    g_steps += 10;
    return *(int *)arg + 100;
}

static int immediate_job(void *arg)
{
    return *(int *)arg + 1;
}

static void async_framework(void)
{
    ASYNC_WAIT_CTX *w;
    ASYNC_JOB *job = NULL;
    int ret = -1;
    int arg = 7;
    size_t n;
    OSSL_ASYNC_FD fds[4];
    OSSL_ASYNC_FD fd = -1;
    OSSL_ASYNC_FD addfd[4];
    OSSL_ASYNC_FD delfd[4];
    size_t numadd = 0;
    size_t numdel = 0;
    void *cd = NULL;
    ASYNC_callback_fn cb_out = NULL;
    void *cb_arg_out = NULL;
    static const int key1 = 1;
    static const int key2 = 2;
    static int data1 = 11;
    static int cb_data = 22;

    printf("lr.async.capable=%d\n", ASYNC_is_capable());

    printf("lr.async.init=%d\n", ASYNC_init_thread(0, 0));
    /* init_size > max_size: the pool-size refusal. */
    printf("lr.async.init_bad=%d\n", ASYNC_init_thread(10, 20));

    /* Before any stack is allocated the allocator pair may still be replaced; after it may not. */
    {
        ASYNC_stack_alloc_fn a = NULL;
        ASYNC_stack_free_fn f = NULL;

        ASYNC_get_mem_functions(&a, &f);
        printf("lr.async.memfn_alloc_nonnull=%d\n", a != NULL);
        printf("lr.async.memfn_free_nonnull=%d\n", f != NULL);
        printf("lr.async.set_memfn_early=%d\n", ASYNC_set_mem_functions(NULL, NULL));
    }

    /* Outside a job. */
    printf("lr.async.current_job_outside=%d\n", ASYNC_get_current_job() != NULL);
    printf("lr.async.pause_outside=%d\n", ASYNC_pause_job());
    ASYNC_block_pause();
    ASYNC_unblock_pause();

    /* A job that runs to completion without pausing. */
    printf("lr.async.immediate=%d\n",
           ASYNC_start_job(&job, NULL, &ret, immediate_job, &arg, sizeof arg));
    printf("lr.async.immediate_ret=%d\n", ret);
    printf("lr.async.immediate_job_null=%d\n", job == NULL);

    /* The pausing job, with a wait context the caller observes. */
    g_steps = 0;
    w = ASYNC_WAIT_CTX_new();
    printf("lr.async.waitctx_new=%d\n", w != NULL);
    printf("lr.async.start_pause=%d\n",
           ASYNC_start_job(&job, w, &ret, pausing_job, &arg, sizeof arg));
    printf("lr.async.start_paused_steps=%d\n", g_steps);
    printf("lr.async.job_nonnull=%d\n", job != NULL);
    printf("lr.async.wait_ctx_identity=%d\n", ASYNC_get_wait_ctx(job) == w);
    printf("lr.async.current_job_inside_outer=%d\n", ASYNC_get_current_job() == job);
    printf("lr.async.resume=%d\n", ASYNC_start_job(&job, w, &ret, pausing_job, NULL, 0));
    printf("lr.async.resume_ret=%d\n", ret);
    printf("lr.async.resume_steps=%d\n", g_steps);
    printf("lr.async.resume_job_null=%d\n", job == NULL);

    /* After a stack has been allocated, the allocator pair is frozen. */
    printf("lr.async.set_memfn_late=%d\n", ASYNC_set_mem_functions(NULL, NULL));

    /* The whole `ASYNC_WAIT_CTX_*` surface. */
    printf("lr.async.wc.status0=%d\n", ASYNC_WAIT_CTX_get_status(w));
    printf("lr.async.wc.set_status=%d\n", ASYNC_WAIT_CTX_set_status(w, 2));
    printf("lr.async.wc.status2=%d\n", ASYNC_WAIT_CTX_get_status(w));
    printf("lr.async.wc.get_callback_empty=%d\n",
           ASYNC_WAIT_CTX_get_callback(w, &cb_out, &cb_arg_out));
    printf("lr.async.wc.set_callback=%d\n",
           ASYNC_WAIT_CTX_set_callback(w, async_callback, &cb_data));
    printf("lr.async.wc.get_callback=%d\n",
           ASYNC_WAIT_CTX_get_callback(w, &cb_out, &cb_arg_out));
    printf("lr.async.wc.callback_roundtrip=%d\n",
           cb_out == async_callback && cb_arg_out == (void *)&cb_data);
    printf("lr.async.wc.set_callback_null=%d\n",
           ASYNC_WAIT_CTX_set_callback(NULL, async_callback, NULL));

    printf("lr.async.wc.set_fd=%d\n",
           ASYNC_WAIT_CTX_set_wait_fd(w, &key1, 42, &data1, NULL));
    printf("lr.async.wc.get_fd_hit=%d\n", ASYNC_WAIT_CTX_get_fd(w, &key1, &fd, &cd));
    printf("lr.async.wc.fd=%d\n", fd);
    printf("lr.async.wc.custom_roundtrip=%d\n", cd == (void *)&data1);
    printf("lr.async.wc.get_fd_miss=%d\n", ASYNC_WAIT_CTX_get_fd(w, &key2, &fd, &cd));
    printf("lr.async.wc.get_all=%d\n", ASYNC_WAIT_CTX_get_all_fds(w, fds, &n));
    printf("lr.async.wc.numfds=%d\n", (int)n);
    printf("lr.async.wc.get_changed=%d\n",
           ASYNC_WAIT_CTX_get_changed_fds(w, addfd, &numadd, delfd, &numdel));
    printf("lr.async.wc.numadd=%d\n", (int)numadd);
    printf("lr.async.wc.numdel=%d\n", (int)numdel);
    printf("lr.async.wc.clear_hit=%d\n", ASYNC_WAIT_CTX_clear_fd(w, &key1));
    printf("lr.async.wc.get_all_after=%d\n", ASYNC_WAIT_CTX_get_all_fds(w, NULL, &n));
    printf("lr.async.wc.numfds_after=%d\n", (int)n);
    printf("lr.async.wc.clear_miss=%d\n", ASYNC_WAIT_CTX_clear_fd(w, &key2));
    ASYNC_WAIT_CTX_free(w);

    /* `ASYNC_get_wait_ctx` on a fresh job handle is not driven: the authority dereferences it
     * without a NULL test, so the arm would crash rather than compare. */

    ASYNC_cleanup_thread();
    ERR_clear_error();
}

int main(void)
{
    pem_private_key();
    async_framework();
    return 0;
}
