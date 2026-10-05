/*
 * RT-HOSTILE-X509 — the Phase 18 hostile X.509 / malformed-input corpus, driven through the
 * candidate's X.509, ASN.1 and PEM readers, with per-entry crash / OOM / timeout detection.
 *
 * What it drives
 * --------------
 * `courts/phase18/fixtures/hostile-x509/` holds one file per corpus entry, named
 * `<arm>__<id>.bin`. The arm selects the reader entry point the bytes are fed to:
 *
 *   cert   d2i_X509                 crl    d2i_X509_CRL          req    d2i_X509_REQ
 *   xext   d2i_X509_EXTENSION       xexts  d2i_X509_EXTENSIONS   gn     d2i_GENERAL_NAMES
 *   atype  d2i_ASN1_TYPE            gtime  d2i_ASN1_GENERALIZEDTIME
 *   utime  d2i_ASN1_UTCTIME         alg    d2i_X509_ALGOR        spki   d2i_X509_PUBKEY
 *   pemcert PEM_read_bio_X509       pemcrl PEM_read_bio_X509_CRL pemreq PEM_read_bio_X509_REQ
 *
 * `xext` additionally drives the extension *body* parser (`X509V3_EXT_d2i`) so malformed
 * subjectAltName / nameConstraints / basicConstraints bodies reach the v3 readers; `xexts`
 * drives a sequence of extensions so duplicate / unknown / critical mixtures are exercised.
 * The corpus is a fixed enumeration, not a fuzzer, and **not a coverage claim** (section 3.1).
 *
 * One entry per process, because a hostile input may not terminate
 * -----------------------------------------------------------------
 * Section 3.3 of `docs/PHASE-18-SUBPHASES.md`: a crash, an exhausted allocation budget or a
 * failure to terminate is a *recorded finding* for that entry, not a harness abort. So the
 * probe forks once per entry. A child killed by a signal is `crash`; a child that reports an
 * allocation failure under the process's own `RLIMIT_DATA` is `oom`; a child that does not
 * finish inside `ENTRY_TIMEOUT_MS` is killed and recorded `timeout`. The parent's own exit
 * status is always 0, so a crashing input cannot take the court down with it.
 *
 * The transcript is a property of the library
 * -------------------------------------------
 * The parent prints one fixed-schema `key=value` block per entry, whether the child reported a
 * disposition, crashed, or timed out, so the two sides' observation counts always agree and a
 * missing entry can never read as a shorter, silent transcript. Nothing printed is derived
 * from the probe's own frame, the clock, an address or a random field: only the library's
 * return values (the `d2i_*` / `PEM_read_bio_*` result, the `ERR` queue, and the parsed
 * object's own version / extension count / NIDs / re-encoded bytes reduced to a 64-bit FNV-1a
 * digest).
 *
 * It is compiled twice, once against the admitted authority's prefix and once against the
 * candidate distribution shell, and the two transcripts are diffed. It is NOT a memory-safety
 * or security proof: it is a bounded differential result over the corpus it drives (section
 * 3.1).
 *
 * argv: [corpus-dir]   (default /work/courts/phase18/fixtures/hostile-x509)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define DEFAULT_CORPUS "/work/courts/phase18/fixtures/hostile-x509"

#define ENTRY_TIMEOUT_MS 4000
#define CHILD_OOM 42
#define MAX_ENTRIES 512
#define MAX_NAME 256
#define MAX_ARM 32

/* A child's disposition, written to the parent over a pipe. */
struct result {
    int reported;
    int oom;
    int ret;                    /* 1 == the reader returned a non-NULL object */
    int obs;                    /* arm-specific: version / NID / name count ... */
    int obs2;                   /* arm-specific: ext count / body-decoded flag ... */
    unsigned long long digest;  /* FNV-1a of arm-specific re-encoded bytes */
    char err[40];               /* "lib.reason" of the first queued error, or "none" */
};

struct entry {
    char name[MAX_NAME];
    char id[MAX_NAME];
    char arm[MAX_ARM];
};

/* ---------------------------------------------------------------------------------------------
 * Output helpers -- every line is `key=value`. No address is ever printed.
 * --------------------------------------------------------------------------------------------- */

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_str(const char *key, const char *v)
{
    printf("%s=%s\n", key, v != NULL ? v : "");
}

static unsigned long long fnv1a(const unsigned char *b, size_t n)
{
    unsigned long long h = 1469598103934665603ULL;
    size_t i;

    for (i = 0; i < n; i++) {
        h ^= (unsigned long long)b[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* Read a whole file into a fresh buffer. Returns 0 on success. */
static int read_file(const char *path, unsigned char **out, long *len)
{
    FILE *f = fopen(path, "rb");
    long n;
    unsigned char *buf;

    if (f == NULL)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    n = ftell(f);
    if (n < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    buf = malloc(n > 0 ? (size_t)n : 1);
    if (buf == NULL) {
        fclose(f);
        return -1;
    }
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);
    *out = buf;
    *len = n;
    return 0;
}

/* Drain up to four errors; record the first reason and whether any was an allocation
 * failure. This is also the OOM detector: a failed allocation inside the library raises
 * `ERR_R_MALLOC_FAILURE`, which the process's own RLIMIT_DATA (and the container cap) is what
 * can actually cause. */
static void drain_errors(struct result *r)
{
    int i;
    unsigned long e;

    snprintf(r->err, sizeof r->err, "%s", "none");
    for (i = 0; i < 4 && (e = ERR_get_error()) != 0; i++) {
        if (i == 0)
            snprintf(r->err, sizeof r->err, "%d.%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
        if ((int)ERR_GET_REASON(e) == ERR_R_MALLOC_FAILURE)
            r->oom = 1;
    }
    ERR_clear_error();
}

static unsigned long long name_digest(X509_NAME *name)
{
    char *s;
    unsigned long long h = 0;

    if (name == NULL)
        return 0;
    s = X509_NAME_oneline(name, NULL, 0);
    if (s == NULL)
        return 0;
    h = fnv1a((const unsigned char *)s, strlen(s));
    OPENSSL_free(s);
    return h;
}

/* ---------------------------------------------------------------------------------------------
 * The arms. Each sets r->ret, r->obs, r->obs2 and r->digest for its reader.
 * --------------------------------------------------------------------------------------------- */

static void arm_cert(const unsigned char *buf, long n, struct result *r)
{
    const unsigned char *p = buf;
    X509 *x = d2i_X509(NULL, &p, n);

    r->ret = x != NULL;
    if (x != NULL) {
        r->obs = X509_get_version(x);
        r->obs2 = X509_get_ext_count(x);
        r->digest = name_digest(X509_get_subject_name(x)) ^ name_digest(X509_get_issuer_name(x));
        X509_free(x);
    }
}

static void arm_crl(const unsigned char *buf, long n, struct result *r)
{
    const unsigned char *p = buf;
    X509_CRL *x = d2i_X509_CRL(NULL, &p, n);

    r->ret = x != NULL;
    if (x != NULL) {
        r->obs = X509_CRL_get_version(x);
        r->obs2 = X509_CRL_get_ext_count(x);
        r->digest = name_digest(X509_CRL_get_issuer(x));
        X509_CRL_free(x);
    }
}

static void arm_req(const unsigned char *buf, long n, struct result *r)
{
    const unsigned char *p = buf;
    X509_REQ *x = d2i_X509_REQ(NULL, &p, n);

    r->ret = x != NULL;
    if (x != NULL) {
        r->obs = X509_REQ_get_version(x);
        r->obs2 = X509_REQ_get_attr_count(x);
        r->digest = name_digest(X509_REQ_get_subject_name(x));
        X509_REQ_free(x);
    }
}

static void arm_xext(const unsigned char *buf, long n, struct result *r)
{
    const unsigned char *p = buf;
    X509_EXTENSION *x = d2i_X509_EXTENSION(NULL, &p, n);

    r->ret = x != NULL;
    if (x != NULL) {
        ASN1_OCTET_STRING *d = X509_EXTENSION_get_data(x);
        void *body;

        r->obs = OBJ_obj2nid(X509_EXTENSION_get_object(x));
        body = X509V3_EXT_d2i(x);       /* drives the SAN / NC / BC body parser */
        r->obs2 = body != NULL;
        if (body != NULL) {
            /* The decoded body's type varies; leaking it in the child is deliberate -- the
             * child exits after this entry, so a type-specific free is not needed here. */
        }
        if (d != NULL)
            r->digest = fnv1a(ASN1_STRING_get0_data(d), (size_t)ASN1_STRING_length(d));
        X509_EXTENSION_free(x);
    }
}

static void arm_xexts(const unsigned char *buf, long n, struct result *r)
{
    const unsigned char *p = buf;
    X509_EXTENSIONS *st = d2i_X509_EXTENSIONS(NULL, &p, n);

    r->ret = st != NULL;
    if (st != NULL) {
        int i, count = OPENSSL_sk_num((const OPENSSL_STACK *)st);
        int decoded = 0;
        unsigned long long h = 0;

        for (i = 0; i < count; i++) {
            X509_EXTENSION *e = OPENSSL_sk_value((const OPENSSL_STACK *)st, i);

            if (e == NULL)
                continue;
            if (X509V3_EXT_d2i(e) != NULL)
                decoded++;
            {
                ASN1_OCTET_STRING *d = X509_EXTENSION_get_data(e);

                if (d != NULL)
                    h ^= fnv1a(ASN1_STRING_get0_data(d),
                               (size_t)ASN1_STRING_length(d));
            }
        }
        r->obs = count;
        r->obs2 = decoded;
        r->digest = h;
        OPENSSL_sk_pop_free((OPENSSL_STACK *)st, (OPENSSL_sk_freefunc)X509_EXTENSION_free);
    }
}

static void arm_gn(const unsigned char *buf, long n, struct result *r)
{
    const unsigned char *p = buf;
    GENERAL_NAMES *x = d2i_GENERAL_NAMES(NULL, &p, n);

    r->ret = x != NULL;
    if (x != NULL) {
        unsigned char *der = NULL;
        int dl = i2d_GENERAL_NAMES(x, &der);

        r->obs = OPENSSL_sk_num((const OPENSSL_STACK *)x);
        if (dl > 0 && der != NULL)
            r->digest = fnv1a(der, (size_t)dl);
        OPENSSL_free(der);
        OPENSSL_sk_pop_free((OPENSSL_STACK *)x, (OPENSSL_sk_freefunc)GENERAL_NAME_free);
    }
}

static void arm_atype(const unsigned char *buf, long n, struct result *r)
{
    const unsigned char *p = buf;
    ASN1_TYPE *x = d2i_ASN1_TYPE(NULL, &p, n);

    r->ret = x != NULL;
    if (x != NULL) {
        unsigned char *der = NULL;
        int dl = i2d_ASN1_TYPE(x, &der);

        r->obs = ASN1_TYPE_get(x);
        if (dl > 0 && der != NULL)
            r->digest = fnv1a(der, (size_t)dl);
        OPENSSL_free(der);
        ASN1_TYPE_free(x);
    }
}

static void arm_gtime(const unsigned char *buf, long n, struct result *r)
{
    const unsigned char *p = buf;
    ASN1_GENERALIZEDTIME *x = d2i_ASN1_GENERALIZEDTIME(NULL, &p, n);

    r->ret = x != NULL;
    if (x != NULL) {
        r->obs = ASN1_TIME_check((const ASN1_TIME *)x);
        r->digest = fnv1a(ASN1_STRING_get0_data(x), (size_t)ASN1_STRING_length(x));
        ASN1_GENERALIZEDTIME_free(x);
    }
}

static void arm_utime(const unsigned char *buf, long n, struct result *r)
{
    const unsigned char *p = buf;
    ASN1_UTCTIME *x = d2i_ASN1_UTCTIME(NULL, &p, n);

    r->ret = x != NULL;
    if (x != NULL) {
        r->obs = ASN1_TIME_check((const ASN1_TIME *)x);
        r->digest = fnv1a(ASN1_STRING_get0_data(x), (size_t)ASN1_STRING_length(x));
        ASN1_UTCTIME_free(x);
    }
}

static void arm_alg(const unsigned char *buf, long n, struct result *r)
{
    const unsigned char *p = buf;
    X509_ALGOR *x = d2i_X509_ALGOR(NULL, &p, n);

    r->ret = x != NULL;
    if (x != NULL) {
        unsigned char *der = NULL;
        int dl = i2d_X509_ALGOR(x, &der);

        if (dl > 0 && der != NULL)
            r->digest = fnv1a(der, (size_t)dl);
        OPENSSL_free(der);
        X509_ALGOR_free(x);
    }
}

static void arm_spki(const unsigned char *buf, long n, struct result *r)
{
    const unsigned char *p = buf;
    X509_PUBKEY *x = d2i_X509_PUBKEY(NULL, &p, n);

    r->ret = x != NULL;
    if (x != NULL) {
        unsigned char *der = NULL;
        int dl = i2d_X509_PUBKEY(x, &der);

        if (dl > 0 && der != NULL)
            r->digest = fnv1a(der, (size_t)dl);
        OPENSSL_free(der);
        X509_PUBKEY_free(x);
    }
}

static BIO *mem_bio(const unsigned char *buf, long n)
{
    return BIO_new_mem_buf(buf, (int)n);
}

static void arm_pemcert(const unsigned char *buf, long n, struct result *r)
{
    BIO *b = mem_bio(buf, n);
    X509 *x = b != NULL ? PEM_read_bio_X509(b, NULL, NULL, NULL) : NULL;

    r->ret = x != NULL;
    if (x != NULL) {
        r->obs = X509_get_version(x);
        r->obs2 = X509_get_ext_count(x);
        r->digest = name_digest(X509_get_subject_name(x));
        X509_free(x);
    }
    BIO_free(b);
}

static void arm_pemcrl(const unsigned char *buf, long n, struct result *r)
{
    BIO *b = mem_bio(buf, n);
    X509_CRL *x = b != NULL ? PEM_read_bio_X509_CRL(b, NULL, NULL, NULL) : NULL;

    r->ret = x != NULL;
    if (x != NULL) {
        r->obs = X509_CRL_get_version(x);
        r->obs2 = X509_CRL_get_ext_count(x);
        r->digest = name_digest(X509_CRL_get_issuer(x));
        X509_CRL_free(x);
    }
    BIO_free(b);
}

static void arm_pemreq(const unsigned char *buf, long n, struct result *r)
{
    BIO *b = mem_bio(buf, n);
    X509_REQ *x = b != NULL ? PEM_read_bio_X509_REQ(b, NULL, NULL, NULL) : NULL;

    r->ret = x != NULL;
    if (x != NULL) {
        r->obs = X509_REQ_get_version(x);
        r->obs2 = X509_REQ_get_attr_count(x);
        r->digest = name_digest(X509_REQ_get_subject_name(x));
        X509_REQ_free(x);
    }
    BIO_free(b);
}

/* Fill `r` with the disposition of driving `path` with `arm`. */
static void drive(const char *path, const char *arm, struct result *r)
{
    unsigned char *buf = NULL;
    long n = 0;

    memset(r, 0, sizeof *r);
    r->ret = -1000;
    snprintf(r->err, sizeof r->err, "%s", "setup");

    if (read_file(path, &buf, &n) != 0) {
        r->reported = 1;
        return;
    }
    ERR_clear_error();

    if (strcmp(arm, "cert") == 0)
        arm_cert(buf, n, r);
    else if (strcmp(arm, "crl") == 0)
        arm_crl(buf, n, r);
    else if (strcmp(arm, "req") == 0)
        arm_req(buf, n, r);
    else if (strcmp(arm, "xext") == 0)
        arm_xext(buf, n, r);
    else if (strcmp(arm, "xexts") == 0)
        arm_xexts(buf, n, r);
    else if (strcmp(arm, "gn") == 0)
        arm_gn(buf, n, r);
    else if (strcmp(arm, "atype") == 0)
        arm_atype(buf, n, r);
    else if (strcmp(arm, "gtime") == 0)
        arm_gtime(buf, n, r);
    else if (strcmp(arm, "utime") == 0)
        arm_utime(buf, n, r);
    else if (strcmp(arm, "alg") == 0)
        arm_alg(buf, n, r);
    else if (strcmp(arm, "spki") == 0)
        arm_spki(buf, n, r);
    else if (strcmp(arm, "pemcert") == 0)
        arm_pemcert(buf, n, r);
    else if (strcmp(arm, "pemcrl") == 0)
        arm_pemcrl(buf, n, r);
    else if (strcmp(arm, "pemreq") == 0)
        arm_pemreq(buf, n, r);
    else
        snprintf(r->err, sizeof r->err, "%s", "unknown-arm");

    drain_errors(r);
    free(buf);
    r->reported = 1;
}

/* Parse `<arm>__<id>.bin`; return 0 on success. */
static int parse_name(const char *filename, struct entry *e)
{
    const char *sep;
    size_t len = strlen(filename);
    size_t alen;

    if (len < 5 || strcmp(filename + len - 4, ".bin") != 0)
        return -1;
    sep = strstr(filename, "__");
    if (sep == NULL || sep == filename)
        return -1;
    alen = (size_t)(sep - filename);
    if (alen >= sizeof e->arm)
        return -1;
    snprintf(e->arm, sizeof e->arm, "%.*s", (int)alen, filename);
    snprintf(e->name, sizeof e->name, "%s", filename);
    snprintf(e->id, sizeof e->id, "%s", sep + 2);
    {
        char *dot = strstr(e->id, ".bin");

        if (dot != NULL)
            *dot = '\0';
    }
    return 0;
}

static int cmp_entry(const void *a, const void *b)
{
    const struct entry *ea = a;
    const struct entry *eb = b;

    return strcmp(ea->name, eb->name);
}

/* One fixed-schema block per entry. signum is non-zero only for a crash. */
static void emit(const struct entry *e, const char *cls, int signum,
                 const struct result *r)
{
    char key[2 * MAX_NAME + 16];

#define EMIT_INT(field, value) do { \
        snprintf(key, sizeof key, "entry.%s." field, e->id); \
        out_int(key, (long)(value)); \
    } while (0)
#define EMIT_STR(field, value) do { \
        snprintf(key, sizeof key, "entry.%s." field, e->id); \
        out_str(key, (value)); \
    } while (0)

    EMIT_STR("class", cls);
    EMIT_STR("arm", e->arm);
    EMIT_INT("signal", signum);
    EMIT_INT("ret", r->ret);
    EMIT_INT("obs", r->obs);
    EMIT_INT("obs2", r->obs2);
    snprintf(key, sizeof key, "entry.%s.digest", e->id);
    printf("%s=%016llx\n", key, r->digest);
    EMIT_STR("err", r->err);

#undef EMIT_INT
#undef EMIT_STR
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : DEFAULT_CORPUS;
    struct entry entries[MAX_ENTRIES];
    int n_entries = 0;
    DIR *d;
    struct dirent *de;
    int i;

    setvbuf(stdout, NULL, _IOLBF, 0);

    d = opendir(dir);
    if (d == NULL) {
        fprintf(stderr, "hostile-x509: cannot open corpus %s: %s\n", dir, strerror(errno));
        return 2;
    }
    while ((de = readdir(d)) != NULL && n_entries < MAX_ENTRIES) {
        if (parse_name(de->d_name, &entries[n_entries]) == 0)
            n_entries++;
    }
    closedir(d);
    qsort(entries, (size_t)n_entries, sizeof entries[0], cmp_entry);

    out_int("corpus.entries", n_entries);

    for (i = 0; i < n_entries; i++) {
        int pipefd[2];
        pid_t pid;
        struct result r;
        int class_timeout = 0;
        int status = 0;
        struct timespec t0;
        char path[512];

        memset(&r, 0, sizeof r);
        r.ret = -1000;
        snprintf(r.err, sizeof r.err, "%s", "setup");

        if (pipe(pipefd) != 0) {
            emit(&entries[i], "probe-error", 0, &r);
            continue;
        }
        snprintf(path, sizeof path, "%s/%s", dir, entries[i].name);
        pid = fork();
        if (pid < 0) {
            close(pipefd[0]);
            close(pipefd[1]);
            emit(&entries[i], "probe-error", 0, &r);
            continue;
        }
        if (pid == 0) {
            struct result cr;
            const char *src;
            ssize_t off = 0;

            close(pipefd[0]);
            drive(path, entries[i].arm, &cr);
            src = (const char *)&cr;
            while (off < (ssize_t)sizeof cr) {
                ssize_t k = write(pipefd[1], src + off, sizeof cr - (size_t)off);

                if (k <= 0)
                    break;
                off += k;
            }
            close(pipefd[1]);
            _exit(cr.oom ? CHILD_OOM : 0);
        }

        close(pipefd[1]);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (;;) {
            pid_t w = waitpid(pid, &status, WNOHANG);
            struct timespec now;
            long elapsed_ms;

            if (w == pid)
                break;
            if (w < 0 && errno != EINTR)
                break;
            clock_gettime(CLOCK_MONOTONIC, &now);
            elapsed_ms = (now.tv_sec - t0.tv_sec) * 1000L
                       + (now.tv_nsec - t0.tv_nsec) / 1000000L;
            if (elapsed_ms > ENTRY_TIMEOUT_MS) {
                class_timeout = 1;
                kill(pid, SIGKILL);
                while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
                    ;
                break;
            }
            {
                struct timespec s = { 0, 2000000 }; /* 2 ms */

                nanosleep(&s, NULL);
            }
        }
        /* The child writes the struct once before exiting. A crash writes nothing, so the
         * parent's defaults stand. */
        {
            ssize_t got = 0;
            char *dst = (char *)&r;

            while (got < (ssize_t)sizeof r) {
                ssize_t k = read(pipefd[0], dst + got, sizeof r - (size_t)got);

                if (k > 0) {
                    got += k;
                    continue;
                }
                break;
            }
        }
        close(pipefd[0]);

        if (class_timeout)
            emit(&entries[i], "timeout", 0, &r);
        else if (WIFSIGNALED(status))
            emit(&entries[i], "crash", WTERMSIG(status), &r);
        else if (WIFEXITED(status) && WEXITSTATUS(status) == CHILD_OOM)
            emit(&entries[i], "oom", 0, &r);
        else if (WIFEXITED(status))
            emit(&entries[i], "parse", 0, &r);
        else
            emit(&entries[i], "probe-error", 0, &r);
    }

    printf("probe.done=1\n");
    return 0;
}
