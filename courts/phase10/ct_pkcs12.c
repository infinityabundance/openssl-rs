/*
 * openssl-rs — the PKCS#12 KDF construction probe (CT-PKCS12).
 *
 * This program is compiled **once**, against the candidate distribution shell alone, and its
 * answers are compared with the expected bytes the pinned corpus holds. There is no authority
 * transcript: the differential question — "does the candidate behave like the admitted
 * authority?" — is `RT-PKCS12`'s. This is the second, independent plane, and it exists because a
 * differential court only proves agreement: two implementations can agree byte for byte and both
 * be wrong (`forensics/tools/correctness_vectors.py`'s header, D201/D208). A published construction
 * vector closes a derived value. Like `ct_digest.c`, `ct_cipher.c` and `ct_drbg.c` this driver
 * **computes and never decides**: it prints one result line per expected key and returns 0.
 *
 * The subject and the input file
 * ------------------------------
 * `crypto/pkcs12/p12_key.c`'s `PKCS12_key_gen_uni`, driven through the public `pkcs12.h` surface,
 * against the pinned tree's own `test/recipes/30-test_evp_data/evppbe_pkcs12.txt`. That file's
 * `PBE = pkcs12` stanzas are `test/evp_test.c`'s `pbe_test` cases, whose `pbe_test_run`
 * (`test/evp_test.c:3425-3439`) fetches the stanza's `MD` and calls
 * `PKCS12_key_gen_uni(pass, pass_len, salt, salt_len, id, iter, key_len, key, md)`. The probe
 * reproduces that call exactly, and `PKCS12_key_gen_uni` reaches the provider `PKCS12KDF` row.
 *
 * The program is invoked with **one argument, the path of that corpus file**, and re-reads the
 * stanza's inputs from it, exactly as `ct_drbg.c` does: `forensics/vectors/pkcs12.json` carries
 * only the *expected* bytes, and re-reading the corpus is the point of this plane — a value that is
 * re-read cannot be a transcription error. The positional label rule below is reproduced by
 * `forensics/tools/gen_pkcs12_vectors.py`, so the two sides' labels align without either reading
 * the other.
 *
 * Protocol
 * --------
 * The program writes, to stdout, one line per vector:
 *
 *     ct.pkcs12.<NN>=<hex>
 *
 * and finally `ct.done=1`. `<NN>` is the two-digit *emitted-stanza index* in file order, the
 * generator's `pkcs12.NN` label; `<hex>` is the lowercase hex of the `Key`-length output the
 * derivation produced. A stanza whose fields are incomplete or whose derivation fails prints
 * `ct.pkcs12.<NN>=FAIL`, which is a value no vector expects, so a defective run fails loudly
 * rather than silently skipping a vector.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pkcs12.h>

#define CT_LINE_LEN 1024
#define CT_MAX_BYTES 512

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
    }
    while (*s >= '0' && *s <= '9')
        v = v * 10 + (*s++ - '0');
    return neg ? -v : v;
}

/* One accumulated `PBE = pkcs12` stanza. `pbe` distinguishes "not yet seen" (0), "seen" (1), and
 * "some other PBE name" (-1), so the flush can ignore the `Title =` stanza and any pbkdf2 stanza. */
struct ct_p12 {
    int pbe;
    int have_id, have_iter;
    int id, iter;
    char md[64];
    unsigned char pass[CT_MAX_BYTES];
    size_t pass_len;
    unsigned char salt[CT_MAX_BYTES];
    size_t salt_len;
    unsigned char key[CT_MAX_BYTES];
    size_t key_len;
};

static void ct_flush(struct ct_p12 *s, int *emitted)
{
    unsigned char out[CT_MAX_BYTES];
    EVP_MD *md = NULL;
    int rc;

    if (s->pbe != 1)
        return;
    if (!s->have_id || !s->have_iter || s->md[0] == '\0'
        || s->key_len == 0 || s->key_len > CT_MAX_BYTES) {
        printf("ct.pkcs12.%02d=FAIL\n", *emitted);
        (*emitted)++;
        return;
    }

    md = EVP_MD_fetch(NULL, s->md, NULL);
    if (md == NULL) {
        printf("ct.pkcs12.%02d=FAIL\n", *emitted);
        (*emitted)++;
        return;
    }
    rc = PKCS12_key_gen_uni(s->pass, (int)s->pass_len, s->salt, (int)s->salt_len,
                            s->id, s->iter, (int)s->key_len, out, md);
    if (rc == 0) {
        printf("ct.pkcs12.%02d=FAIL\n", *emitted);
    } else {
        printf("ct.pkcs12.%02d=", *emitted);
        ct_hex(out, s->key_len);
        putchar('\n');
    }
    (*emitted)++;
    EVP_MD_free(md);
}

int main(int argc, char **argv)
{
    FILE *f;
    char line[CT_LINE_LEN];
    struct ct_p12 s;
    int emitted = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <evppbe_pkcs12.txt>\n", argv[0]);
        return 2;
    }
    f = fopen(argv[1], "r");
    if (f == NULL) {
        fprintf(stderr, "cannot open %s\n", argv[1]);
        return 2;
    }

    memset(&s, 0, sizeof(s));
    while (fgets(line, sizeof(line), f) != NULL) {
        char *p = line, *eq, *key, *value;
        size_t n = strlen(line);

        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0') {
            ct_flush(&s, &emitted);
            memset(&s, 0, sizeof(s));
            continue;
        }
        if (*p == '#')
            continue;
        eq = strchr(p, '=');
        if (eq == NULL)
            continue;
        *eq = '\0';
        key = p;
        value = eq + 1;
        /* trim key's trailing spaces and value's leading spaces */
        {
            char *e = key + strlen(key);

            while (e > key && (e[-1] == ' ' || e[-1] == '\t'))
                *--e = '\0';
            while (*value == ' ' || *value == '\t')
                value++;
        }

        if (strcmp(key, "PBE") == 0) {
            s.pbe = (strcmp(value, "pkcs12") == 0) ? 1 : -1;
        } else if (s.pbe == 1) {
            if (strcmp(key, "id") == 0) {
                s.id = ct_int(value);
                s.have_id = 1;
            } else if (strcmp(key, "iter") == 0) {
                s.iter = ct_int(value);
                s.have_iter = 1;
            } else if (strcmp(key, "MD") == 0) {
                snprintf(s.md, sizeof(s.md), "%s", value);
            } else if (strcmp(key, "Password") == 0) {
                if (ct_unhex(value, s.pass, sizeof(s.pass), &s.pass_len) != 0)
                    s.pass_len = 0;
            } else if (strcmp(key, "Salt") == 0) {
                if (ct_unhex(value, s.salt, sizeof(s.salt), &s.salt_len) != 0)
                    s.salt_len = 0;
            } else if (strcmp(key, "Key") == 0) {
                if (ct_unhex(value, s.key, sizeof(s.key), &s.key_len) != 0)
                    s.key_len = 0;
            }
        }
    }
    ct_flush(&s, &emitted);
    fclose(f);

    printf("ct.done=1\n");
    return 0;
}
