/*
 * openssl-rs — the DRBG construction probe (CT-DRBG).
 *
 * This program is compiled **once**, against the candidate distribution shell alone, and its
 * answers are compared with the expected bytes the pinned corpus holds. There is no authority
 * transcript: the differential question — "does the candidate behave like the admitted
 * authority?" — is `RT-DRBG`'s. This is the second, independent plane, and it exists because a
 * differential court only proves agreement: two implementations can agree byte for byte and both
 * be wrong (`forensics/tools/correctness_vectors.py`'s header, D400/D406). A published construction
 * vector closes a derived value. Like `ct_digest.c` and `ct_cipher.c` this driver **computes and
 * never decides**: it prints one result line per expected key and returns 0.
 *
 * The subject and the input file
 * ------------------------------
 * The three default-provider `OSSL_OP_RAND` DRBG rows — `CTR-DRBG`, `HASH-DRBG`, `HMAC-DRBG` —
 * driven through the public `EVP_RAND_*` surface, against NIST CAVP `drbgtestvectors.zip` as the
 * pinned tree already carries it in
 * `test/recipes/30-test_evp_data/evprand.txt`.
 *
 * The program is invoked with **one argument, the path of that corpus file**, and re-reads the
 * stanza's inputs from it. It deliberately does not receive the inputs on the command line or
 * compiled in: `forensics/vectors/drbg.json` carries only the *expected* bytes, and re-reading the
 * corpus is the point of this plane — a value that is re-read cannot be a transcription error
 * (`ct_digest.c` takes a call file for the same reason). The positional label rule below is
 * reproduced by `forensics/tools/gen_drbg_vectors.py`, so the two sides' labels align without
 * either reading the other.
 *
 * Protocol
 * --------
 * The program writes, to stdout, one line per `(vector, key)`:
 *
 *     ct.<label>.<key>=<value>
 *
 * and finally `ct.done=1`. `<label>` is `<drbg-lowercased>.<emitted-stanza-index>` (for example
 * `ctr-drbg.0`), reproduced by the generator. The only key emitted is `output.<n>`, the lowercase
 * hex of the bytes the `n`-th repeat's generate sequence produced (see the generator's `note`
 * for the convention of every key). Nothing else is ever printed: no address, no struct field, no
 * value that is not an `expected` key.
 *
 * The drive, and why it is `test/evp_test.c`'s and not an invented one
 * -------------------------------------------------------------------
 * A CAVP DRBG case is not a bytes-in/bytes-out KAT: it is a seeding case. Entropy and nonce reach
 * a DRBG through the provider's own `get_entropy`/`get_nonce` up-calls, not through
 * `EVP_RAND_instantiate`'s arguments, and the DRBG's settable-ctx-params list does **not** accept
 * `test_entropy`/`test_nonce` — those live on **`TEST-RAND`**. So the probe reproduces
 * `test/evp_test.c`'s `rand_test_run` (`test/evp_test.c:3809-3928`) exactly:
 *
 *   1. fetch `TEST-RAND` and build the **parent** context; set its `strength` to 256;
 *   2. fetch the vector's DRBG and build the **child** context over that parent;
 *   3. set the child's `use_derivation_function`, `cipher`/`digest`, and the hard-coded `"HMAC"`
 *      MAC through `EVP_RAND_CTX_set_params` (see the note below on the MAC);
 *   4. per repeat: instantiate the **parent** with `test_entropy`/`test_nonce`, instantiate the
 *      **child** with the prediction-resistance flag and the personalisation string, optionally
 *      reseed, then call `EVP_RAND_generate` **twice** — with `AdditionalInputA` and then
 *      `AdditionalInputB` — and print the bytes of the **second** call, which is the corpus's
 *      `Output.N` (the corpus keeps one output per repeat and `evp_test` compares the value after
 *      the two-generate sequence).
 *
 * `evp_test` sets the MAC to `"HMAC"` on every row and the cipher/digest only where the stanza
 * names one; the probe does the same. A key a row does not list is ignored by its decoder, which
 * is why setting `mac` on `CTR-DRBG` is harmless and why the drive is identical on all three rows.
 *
 * What this probe deliberately does not observe
 * ---------------------------------------------
 *   * **The six `Availablein = fips` stanzas** (`evprand.txt:79925`, `:79932`, `:79941`, `:79953`,
 *     `:79965`, `:79977`). They run only inside the FIPS provider (`test/evp_test.c:5369-5375`),
 *     this profile builds no FIPS module (D310), and four expect a *refusal*
 *     (`Result = EVP_RAND_CTX_set_params`) rather than an output. The probe skips any stanza
 *     carrying `Availablein` or `Result`, so no FIPS-only input is ever driven.
 *   * **The HMAC-DRBG KDF.** `evpkdf_hmac_drbg.txt` is the `EVP_KDF` `HMAC-DRBG-KDF` row, a
 *     different dispatch table; it is a separate court's corpus and is named in the vector file's
 *     `inputs[]` as declined.
 *   * **Any comparison.** The expected bytes and the verdict are `correctness_vectors.py`'s; a
 *     defective probe can only produce a wrong value, never a passing one.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#define CT_MAX_PAIRS   320
#define CT_KEY_LEN     40
#define CT_VAL_LEN     520
#define CT_LINE_LEN    1024
#define CT_MAX_REPEATS 16
#define CT_MAX_BYTES   300

/* One hex-decoded corpus field. `present` distinguishes "absent" from "present and empty", which
 * the DRBG framework treats differently (`evp_test` passes an empty `""` for absent entropy and
 * nonce, and NULL for absent additional input). */
struct ct_field {
    unsigned char b[CT_MAX_BYTES];
    size_t len;
    int present;
};

/* One repeat (`.N`) of a stanza. The nine fields are the corpus's input keys; `Output` is counted,
 * never decoded, because the probe does not compare. */
struct ct_rep {
    struct ct_field entropy, nonce, pers, addin_a, addin_b, pr_a, pr_b, reseed_entropy,
        reseed_addin;
};

static char g_key[CT_MAX_PAIRS][CT_KEY_LEN];
static char g_val[CT_MAX_PAIRS][CT_VAL_LEN];
static int g_npairs;
static struct ct_rep g_rep[CT_MAX_REPEATS];
/* Emitted-stanza counters, one per DRBG, advanced in the corpus's file order. `gen_drbg_vectors.py`
 * derives the label from the same rule, so the two sides agree without reading each other. */
static int g_seq_ctr, g_seq_hash, g_seq_hmac;

static void ct_hex(const unsigned char *b, size_t n)
{
    static const char d[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        putchar(d[b[i] >> 4]);
        putchar(d[b[i] & 0xf]);
    }
}

static int ct_unhex(const char *hex, unsigned char *out, size_t cap, size_t *len)
{
    size_t n = strlen(hex), i;

    if (n % 2 != 0 || n / 2 > cap)
        return -1;
    for (i = 0; i < n; i += 2) {
        unsigned int b;

        if (sscanf(hex + i, "%2x", &b) != 1)
            return -1;
        out[i / 2] = (unsigned char)b;
    }
    *len = n / 2;
    return 0;
}

static int ct_int(const char *s)
{
    int v = 0, neg = 0;

    while (*s == ' ' || *s == '\t')
        s++;
    if (*s == '-') {
        neg = 1;
        s++;
    } else if (*s == '+') {
        s++;
    }
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        s++;
    }
    return neg ? -v : v;
}

static void ct_lower(char *dst, const char *src, size_t cap)
{
    size_t i;

    for (i = 0; i + 1 < cap && src[i] != '\0'; i++)
        dst[i] = (src[i] >= 'A' && src[i] <= 'Z') ? (char)(src[i] + 32) : src[i];
    dst[i] = '\0';
}

/* `<name>.<n>` when the suffix is all digits; else 0. */
static int ct_split(const char *key, char *name, size_t cap, int *idx)
{
    const char *dot = strrchr(key, '.');
    const char *s;
    size_t n;
    int v = 0;

    if (dot == NULL)
        return 0;
    s = dot + 1;
    if (*s == '\0')
        return 0;
    for (; *s != '\0'; s++)
        if (*s < '0' || *s > '9')
            return 0;
    n = (size_t)(dot - key);
    if (n == 0 || n >= cap)
        return 0;
    memcpy(name, key, n);
    name[n] = '\0';
    for (s = dot + 1; *s != '\0'; s++)
        v = v * 10 + (*s - '0');
    *idx = v;
    return 1;
}

static const char *ct_find_plain(const char *key)
{
    int i;

    /* Last-wins, matching `gen_drbg_vectors.py`'s `plain[key] = value`. */
    for (i = g_npairs - 1; i >= 0; i--)
        if (strcmp(g_key[i], key) == 0)
            return g_val[i];
    return NULL;
}

static int ct_slot(const char *name)
{
    if (strcmp(name, "Entropy") == 0)
        return 0;
    if (strcmp(name, "Nonce") == 0)
        return 1;
    if (strcmp(name, "PersonalisationString") == 0)
        return 2;
    if (strcmp(name, "AdditionalInputA") == 0)
        return 3;
    if (strcmp(name, "AdditionalInputB") == 0)
        return 4;
    if (strcmp(name, "EntropyPredictionResistanceA") == 0)
        return 5;
    if (strcmp(name, "EntropyPredictionResistanceB") == 0)
        return 6;
    if (strcmp(name, "ReseedEntropy") == 0)
        return 7;
    if (strcmp(name, "ReseedAdditionalInput") == 0)
        return 8;
    return -1;
}

static struct ct_field *ct_field_of(struct ct_rep *r, int slot)
{
    switch (slot) {
    case 0:
        return &r->entropy;
    case 1:
        return &r->nonce;
    case 2:
        return &r->pers;
    case 3:
        return &r->addin_a;
    case 4:
        return &r->addin_b;
    case 5:
        return &r->pr_a;
    case 6:
        return &r->pr_b;
    case 7:
        return &r->reseed_entropy;
    case 8:
        return &r->reseed_addin;
    default:
        return NULL;
    }
}

static int *ct_seq_for(const char *drbg)
{
    if (strcmp(drbg, "CTR-DRBG") == 0)
        return &g_seq_ctr;
    if (strcmp(drbg, "HASH-DRBG") == 0)
        return &g_seq_hash;
    if (strcmp(drbg, "HMAC-DRBG") == 0)
        return &g_seq_hmac;
    return NULL;
}

/* The body of `rand_test_run` for one repeat. Returns 1 only if the whole chain succeeded and
 * `out` holds the second generate's bytes. */
static int ct_drive_one(const char *drbg, const char *cipher, const char *digest,
                        int use_df, int pr, size_t outlen, struct ct_rep *r,
                        unsigned char *out)
{
    EVP_RAND *prand = NULL, *crand = NULL;
    EVP_RAND_CTX *parent = NULL, *child = NULL;
    OSSL_PARAM p[6];
    unsigned int pstrength = 256u, strength = 0u;
    int use_df_i = use_df;
    int n, rc = 0;

    prand = EVP_RAND_fetch(NULL, "TEST-RAND", NULL);
    if (prand == NULL)
        goto done;
    parent = EVP_RAND_CTX_new(prand, NULL);
    if (parent == NULL)
        goto done;
    p[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &pstrength);
    p[1] = OSSL_PARAM_construct_end();
    if (!EVP_RAND_CTX_set_params(parent, p))
        goto done;

    crand = EVP_RAND_fetch(NULL, drbg, NULL);
    if (crand == NULL)
        goto done;
    child = EVP_RAND_CTX_new(crand, parent);
    if (child == NULL)
        goto done;

    n = 0;
    p[n++] = OSSL_PARAM_construct_int(OSSL_DRBG_PARAM_USE_DF, &use_df_i);
    if (cipher != NULL)
        p[n++] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, (char *)cipher, 0);
    if (digest != NULL)
        p[n++] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, (char *)digest, 0);
    p[n++] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC, (char *)"HMAC", 0);
    p[n] = OSSL_PARAM_construct_end();
    if (!EVP_RAND_CTX_set_params(child, p))
        goto done;

    strength = EVP_RAND_get_strength(child);

    p[0] = OSSL_PARAM_construct_octet_string(
        OSSL_RAND_PARAM_TEST_ENTROPY,
        r->entropy.present ? r->entropy.b : (unsigned char *)"",
        r->entropy.present ? r->entropy.len : 0);
    p[1] = OSSL_PARAM_construct_octet_string(
        OSSL_RAND_PARAM_TEST_NONCE,
        r->nonce.present ? r->nonce.b : (unsigned char *)"",
        r->nonce.present ? r->nonce.len : 0);
    p[2] = OSSL_PARAM_construct_end();
    if (!EVP_RAND_instantiate(parent, strength, 0, NULL, 0, p))
        goto done;

    if (!EVP_RAND_instantiate(child, strength, pr,
                              r->pers.present ? r->pers.b : (unsigned char *)"",
                              r->pers.present ? r->pers.len : 0, NULL))
        goto done;

    if (r->reseed_entropy.present) {
        p[0] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
                                                 r->reseed_entropy.b, r->reseed_entropy.len);
        p[1] = OSSL_PARAM_construct_end();
        if (!EVP_RAND_CTX_set_params(parent, p))
            goto done;
        if (!EVP_RAND_reseed(child, pr, NULL, 0,
                             r->reseed_addin.present ? r->reseed_addin.b : NULL,
                             r->reseed_addin.present ? r->reseed_addin.len : 0))
            goto done;
    }

    if (r->pr_a.present) {
        p[0] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY, r->pr_a.b,
                                                 r->pr_a.len);
        p[1] = OSSL_PARAM_construct_end();
        if (!EVP_RAND_CTX_set_params(parent, p))
            goto done;
    }
    if (!EVP_RAND_generate(child, out, outlen, strength, pr,
                           r->addin_a.present ? r->addin_a.b : NULL,
                           r->addin_a.present ? r->addin_a.len : 0))
        goto done;

    if (r->pr_b.present) {
        p[0] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY, r->pr_b.b,
                                                 r->pr_b.len);
        p[1] = OSSL_PARAM_construct_end();
        if (!EVP_RAND_CTX_set_params(parent, p))
            goto done;
    }
    if (!EVP_RAND_generate(child, out, outlen, strength, pr,
                           r->addin_b.present ? r->addin_b.b : NULL,
                           r->addin_b.present ? r->addin_b.len : 0))
        goto done;

    rc = 1;
done:
    EVP_RAND_CTX_free(child);
    EVP_RAND_free(crand);
    EVP_RAND_CTX_free(parent);
    EVP_RAND_free(prand);
    return rc;
}

static void ct_stanza(const char *label, const char *drbg, const char *cipher,
                      const char *digest, int use_df, int pr, int generate_bits, int nout)
{
    size_t outlen;
    int i;

    if (generate_bits <= 0)
        return;
    outlen = (size_t)generate_bits / 8;
    if (outlen == 0 || outlen > CT_MAX_BYTES)
        return;

    for (i = 0; i < nout; i++) {
        unsigned char out[CT_MAX_BYTES];
        int ok;

        memset(out, 0, sizeof out);
        ok = ct_drive_one(drbg, cipher, digest, use_df, pr, outlen, &g_rep[i], out);
        printf("ct.%s.output.%d=", label, i);
        if (ok)
            ct_hex(out, outlen);
        putchar('\n');
    }
}

/* Decode one stanza's numbered fields and, if it is an in-scope construction case, drive it. */
static void ct_process(void)
{
    const char *drbg = ct_find_plain("RAND");
    const char *cipher = ct_find_plain("Cipher");
    const char *digest = ct_find_plain("Digest");
    const char *v;
    int use_df = 0, pr = 0, gb = 0, maxout = -1, i;
    int *seqp;
    char lc[CT_KEY_LEN], label[CT_KEY_LEN + 8];

    if (ct_find_plain("Availablein") != NULL || ct_find_plain("Result") != NULL)
        return;
    seqp = ct_seq_for(drbg);
    if (seqp == NULL)
        return;

    v = ct_find_plain("DerivationFunction");
    if (v != NULL)
        use_df = ct_int(v) != 0;
    v = ct_find_plain("PredictionResistance");
    if (v != NULL)
        pr = ct_int(v) != 0;
    v = ct_find_plain("GenerateBits");
    if (v != NULL)
        gb = ct_int(v);

    memset(g_rep, 0, sizeof g_rep);
    for (i = 0; i < g_npairs; i++) {
        char name[CT_KEY_LEN];
        int idx, slot;

        if (!ct_split(g_key[i], name, sizeof name, &idx))
            continue;
        if (idx < 0 || idx >= CT_MAX_REPEATS)
            continue;
        if (strcmp(name, "Output") == 0) {
            if (idx > maxout)
                maxout = idx;
            continue;
        }
        slot = ct_slot(name);
        if (slot < 0)
            continue;
        {
            struct ct_field *f = ct_field_of(&g_rep[idx], slot);

            if (f != NULL && ct_unhex(g_val[i], f->b, CT_MAX_BYTES, &f->len) == 0)
                f->present = 1;
        }
    }
    if (maxout < 0)
        return;

    ct_lower(lc, drbg, sizeof lc);
    snprintf(label, sizeof label, "%s.%d", lc, *seqp);
    (*seqp)++;
    ct_stanza(label, drbg, cipher, digest, use_df, pr, gb, maxout + 1);
}

static void ct_flush(void)
{
    if (g_npairs == 0)
        return;
    if (ct_find_plain("RAND") != NULL)
        ct_process();
    g_npairs = 0;
}

int main(int argc, char **argv)
{
    FILE *fp;
    char line[CT_LINE_LEN];

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc < 2) {
        fprintf(stderr, "usage: %s <evprand.txt>\n", argv[0]);
        return 1;
    }
    fp = fopen(argv[1], "r");
    if (fp == NULL) {
        fprintf(stderr, "ct_drbg: cannot open %s\n", argv[1]);
        return 1;
    }

    while (fgets(line, sizeof line, fp) != NULL) {
        char *p = line;
        char *eq;
        size_t n;

        n = strlen(p);
        while (n > 0 && (p[n - 1] == '\n' || p[n - 1] == '\r' || p[n - 1] == ' '
                         || p[n - 1] == '\t'))
            p[--n] = '\0';
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0') {
            ct_flush();
            continue;
        }
        if (*p == '#')
            continue;
        eq = strchr(p, '=');
        if (eq == NULL)
            continue;
        *eq = '\0';
        {
            char *key = p;
            char *val = eq + 1;

            n = strlen(key);
            while (n > 0 && (key[n - 1] == ' ' || key[n - 1] == '\t'))
                key[--n] = '\0';
            while (*val == ' ' || *val == '\t')
                val++;
            n = strlen(val);
            while (n > 0 && (val[n - 1] == ' ' || val[n - 1] == '\t'))
                val[--n] = '\0';
            if (key[0] != '\0' && g_npairs < CT_MAX_PAIRS) {
                snprintf(g_key[g_npairs], CT_KEY_LEN, "%s", key);
                snprintf(g_val[g_npairs], CT_VAL_LEN, "%s", val);
                g_npairs++;
            }
        }
    }
    ct_flush();
    fclose(fp);

    printf("ct.done=1\n");
    return 0;
}
