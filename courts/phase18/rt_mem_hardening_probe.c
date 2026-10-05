/*
 * RT-MEM-HARDENING — the reduced engine's fixed buffers and its allocation-failure paths.
 *
 * What it drives, and why the boundaries are the ones they are
 * ------------------------------------------------------------
 * 18.4's subject is a *fixed* buffer whose length was previously exceedable — the earlier
 * greater-than-16-KiB write overflow, where `ssl3_write_bytes` handed a caller's whole length to
 * `tls13_encrypt_record`'s `[u8; 16385]` inner buffer for any write larger than
 * `SSL3_RT_MAX_PLAIN_LENGTH` (16384) and smashed the stack. The fix fragments the write at
 * `SSL3_RT_MAX_PLAIN_LENGTH`; this probe drives each attacker-influenced fixed buffer **at, just
 * below and just above** its recorded capacity (`docs/PHASE-18-SUBPHASES.md` section 3.4) and
 * records the disposition, rather than assuming it. The capacities are the reduced engine's own:
 *
 *   write path        `SSL3_RT_MAX_PLAIN_LENGTH` = 16384, the record-encryption inner buffer and
 *                     the fragment size (`ssl3_write_bytes` / `tls13_encrypt_record`);
 *   handshake read    `TLS13_HS_BUF_LEN` = 16384, the message-reassembly buffer `rd_msg_buf`
 *                     (`tls13_next_handshake_message`);
 *   record read       `Ssl::rec_body` = 17000, the record-body store (`ssl3_read_one_record`).
 *
 * The write cases stand up a full TLS 1.3 client/server flight over memory BIOs (the Phase-17
 * `RT-TLS13-INTEROP` pattern), then `SSL_write` exactly N bytes, drain the records to the peer and
 * read them back. A write of N > 16384 is the concrete overflow case; it must fragment into
 * ceil(N/16384) records. The read cases feed one crafted record into `SSL_accept`: a handshake
 * record whose declared body length is the boundary, and a raw record whose declared length is the
 * `rec_body` boundary. The bytes the reader consumed from the input BIO are reported, because the
 * buffer's bound is exactly where the reader stops consuming.
 *
 * The allocation-failure control, recorded explicitly
 * ---------------------------------------------------
 * Section 3.4 requires the failure path to be *driven*, not assumed. Two arms do that:
 *
 *   * `ctrl-rlimit` injects the container's own bound: the child reads its `VmData` from
 *     `/proc/self/status`, lowers `RLIMIT_DATA` to `VmData + 8 MiB`, and then requests a 256 MiB
 *     `CRYPTO_malloc` — which must fail — and drives `d2i_X509` over a DER that declares a 64 MiB
 *     length. `alloc_null=1` records that the allocation was made to fail; `alloc_malloc_failure`
 *     records whether the engine's own `ERR_R_MALLOC_FAILURE` path was reached;
 *   * `ctrl-hook` installs a wrapper allocator through `CRYPTO_set_mem_functions` that fails the
 *     chosen CRYPTO allocation and then drives `SSL_CTX_new`, recording whether the engine returns
 *     an error (rc 0) or aborts/UB.
 *
 * Whether the engine *handles* the failure or aborts is the measurement; a crash is a recorded
 * finding, not a harness abort.
 *
 * One case per process, so a crash is a finding
 * ---------------------------------------------
 * Each case runs in its own forked child, exactly as the 18.1/18.2 corpus drivers do
 * (`docs/PHASE-18-SUBPHASES.md` section 3.3): a child killed by a signal is `crash`, one that
 * reports an allocation failure under its own limit is `oom`, one that outlives the bound is
 * `timeout`. The parent always exits 0 and prints one fixed-schema block per case whether the
 * child reported, crashed or timed out, so a missing case cannot read as a shorter transcript.
 *
 * It is compiled twice (authority and candidate) and the two transcripts are diffed; a difference
 * is recorded rather than failed, because the reduced engine's dispositions legitimately differ.
 * It is NOT a memory-safety proof and NOT a parity claim: it is a bounded measurement of the
 * boundaries it drives and of the one injected failure (sections 3.1 and 3.6). A buffer that is
 * merely `unsafe` to use — `tls13_encrypt_record`'s inner buffer, which the fragmenting caller
 * bounds but whose own contract does not — is recorded here, not silently fixed.
 *
 * No corpus files and no argv: the cases are fixed, so the probe needs no argument.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#define CERT_FILE "/work/courts/phase17/fixtures/signer.pem"
#define KEY_FILE "/work/courts/phase17/fixtures/rsa-key.pem"

/* `SSL3_RT_MAX_PLAIN_LENGTH` / `TLS13_HS_BUF_LEN` (both 16384) and the body store. */
#define CAP_PLAIN 16384
#define CAP_HSBUF 16384
#define CAP_RECBODY 17000

#define MAX_FLIGHT 3
#define MAX_READS 128
#define CASE_TIMEOUT_MS 20000
#define CHILD_OOM 42

#define FILEID "rt_mem_hardening_probe.c"

enum { K_WRITE, K_READ_HS, K_READ_BODY, K_RLIMIT, K_ASN1, K_HOOK };

struct kase {
    const char *id;
    int kind;
    long n;
    const char *path;
    long capacity;
    const char *phase;
};

/* The fixed case set. Every case prints the same schema; `path`/`capacity`/`phase` carry the
 * boundary's structure so the runner reads it from the transcript rather than typing it twice. */
static const struct kase CASES[] = {
    { "write-below",    K_WRITE,    16383, "write",          CAP_PLAIN,   "below" },
    { "write-at",       K_WRITE,    16384, "write",          CAP_PLAIN,   "at"    },
    { "write-above",    K_WRITE,    16385, "write",          CAP_PLAIN,   "above" },
    { "write-2x",       K_WRITE,    32768, "write",          CAP_PLAIN,   "above" },
    { "write-4x",       K_WRITE,    65536, "write",          CAP_PLAIN,   "above" },
    { "read-hs-below",  K_READ_HS,  16383, "read-handshake", CAP_HSBUF,   "below" },
    { "read-hs-at",     K_READ_HS,  16384, "read-handshake", CAP_HSBUF,   "at"    },
    { "read-hs-above",  K_READ_HS,  16385, "read-handshake", CAP_HSBUF,   "above" },
    { "read-body-below",K_READ_BODY,16999, "read-record",    CAP_RECBODY, "below" },
    { "read-body-at",   K_READ_BODY,17000, "read-record",    CAP_RECBODY, "at"    },
    { "read-body-above",K_READ_BODY,17001, "read-record",    CAP_RECBODY, "above" },
    { "ctrl-rlimit",    K_RLIMIT,   0,     "alloc-rlimit",   0,           "control" },
    { "ctrl-d2i",       K_ASN1,     0,     "alloc-asn1",     0,           "control" },
    { "ctrl-hook",      K_HOOK,     0,     "alloc-hook",     0,           "control" },
};
#define N_CASES ((int)(sizeof CASES / sizeof CASES[0]))

struct result {
    int reported;
    int oom;
    int ret;
    int ssl_error;
    int state;
    int finished;
    int err_count;
    int reason0;
    long bytes;        /* bytes the peer read (write) */
    long consumed;     /* bytes the reader consumed from the input BIO (read) */
    int match;
    int alloc_null;
    int alloc_malloc_failure;
    int d2i_null;
    int rlimit_lowered;
    int alloc_set_rc;
};

static unsigned char g_buf[70000];
static unsigned char g_got[200000];

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_str(const char *key, const char *v)
{
    printf("%s=%s\n", key, v != NULL ? v : "");
}

/* --- the handshake pump, the Phase-17 `RT-TLS13-INTEROP` pattern -------------------------- */

static int drain(BIO *b, unsigned char *buf, int cap)
{
    int total = 0;

    for (;;) {
        int pending = (int)BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL);
        int n;

        if (pending <= 0 || total >= cap)
            break;
        if (pending > cap - total)
            pending = cap - total;
        n = BIO_read(b, buf + total, pending);
        if (n <= 0)
            break;
        total += n;
    }
    return total;
}

/* Drain the error queue, recording the first reason and whether `ERR_R_MALLOC_FAILURE` is seen. */
static void drain_errors(struct result *r)
{
    unsigned long e;
    int i;

    for (i = 0; i < 8 && (e = ERR_get_error()) != 0; i++) {
        if (i == 0)
            r->reason0 = (int)ERR_GET_REASON(e);
        if ((int)ERR_GET_REASON(e) == ERR_R_MALLOC_FAILURE)
            r->alloc_malloc_failure = 1;
    }
    r->err_count = i;
}

/* K_WRITE: a full TLS 1.3 handshake, then an application write of exactly `n` bytes. */
static void drive_write(long n, struct result *r)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *client = NULL, *server = NULL;
    BIO *cr = NULL, *cw = NULL, *sr = NULL, *sw = NULL;
    unsigned char *msg = NULL;
    int i, last_c = -2, last_s = -2;
    int client_owns = 0, server_owns = 0;

    r->ret = -1000;
    r->bytes = -1;
    r->match = -1;

    msg = malloc((size_t)n > 0 ? (size_t)n : 1);
    if (msg == NULL) {
        r->oom = 1;
        return;
    }
    memset(msg, 'A', (size_t)n);

    cctx = SSL_CTX_new(TLS_method());
    sctx = SSL_CTX_new(TLS_method());
    if (cctx == NULL || sctx == NULL)
        goto done;
    (void)SSL_CTX_use_certificate_chain_file(sctx, CERT_FILE);
    (void)SSL_CTX_use_PrivateKey_file(sctx, KEY_FILE, SSL_FILETYPE_PEM);
    (void)SSL_CTX_check_private_key(sctx);
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify(sctx, SSL_VERIFY_NONE, NULL);
    ERR_clear_error();

    client = SSL_new(cctx);
    server = SSL_new(sctx);
    if (client == NULL || server == NULL)
        goto done;
    cr = BIO_new(BIO_s_mem());
    cw = BIO_new(BIO_s_mem());
    sr = BIO_new(BIO_s_mem());
    sw = BIO_new(BIO_s_mem());
    if (cr == NULL || cw == NULL || sr == NULL || sw == NULL)
        goto done;
    SSL_set_bio(client, cr, cw);
    client_owns = 1;
    SSL_set_bio(server, sr, sw);
    server_owns = 1;

    for (i = 0; i < MAX_FLIGHT; i++) {
        int clen, slen;

        last_c = SSL_connect(client);
        clen = drain(cw, g_buf, (int)sizeof g_buf);
        if (clen > 0)
            BIO_write(sr, g_buf, clen);

        last_s = SSL_accept(server);
        slen = drain(sw, g_buf, (int)sizeof g_buf);
        if (slen > 0)
            BIO_write(cr, g_buf, slen);
    }
    r->finished = (last_c > 0 && last_s > 0
                   && SSL_is_init_finished(client) && SSL_is_init_finished(server)) ? 1 : 0;

    if (r->finished) {
        long total = 0;
        int reads = 0;

        r->ret = SSL_write(client, msg, (int)n);
        for (;;) {
            int tw = drain(cw, g_buf, (int)sizeof g_buf);

            if (tw <= 0)
                break;
            BIO_write(sr, g_buf, tw);
        }
        while (reads < MAX_READS) {
            int k = SSL_read(server, g_got, (int)sizeof g_got);

            if (k <= 0)
                break;
            total += k;
            reads++;
            if (total >= n)
                break;
        }
        r->bytes = total;
        r->match = (r->ret == (int)n && total == n) ? 1 : 0;
    }
    drain_errors(r);

done:
    if (client != NULL)
        SSL_free(client);
    if (server != NULL)
        SSL_free(server);
    /* The BIOs were handed to `SSL_set_bio` on success; only free the ones it did not take. */
    if (!client_owns) {
        if (cr != NULL)
            BIO_free(cr);
        if (cw != NULL)
            BIO_free(cw);
    }
    if (!server_owns) {
        if (sr != NULL)
            BIO_free(sr);
        if (sw != NULL)
            BIO_free(sw);
    }
    if (cctx != NULL)
        SSL_CTX_free(cctx);
    if (sctx != NULL)
        SSL_CTX_free(sctx);
    free(msg);
}

/* K_READ_HS / K_READ_BODY: feed one crafted record into `SSL_accept`. */
static void drive_read(long n, int is_hs, struct result *r)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *rbio = NULL, *wbio = NULL, *rbio_keep = NULL;
    unsigned char *rec = NULL;
    long total = 5 + n;
    long pending;

    r->ret = -1000;
    r->bytes = -1;

    rec = malloc((size_t)total);
    if (rec == NULL) {
        r->oom = 1;
        return;
    }
    memset(rec, 0, (size_t)total);
    rec[0] = 22; /* SSL3_RT_HANDSHAKE */
    rec[1] = 0x03;
    rec[2] = 0x03;
    rec[3] = (unsigned char)((n >> 8) & 0xff);
    rec[4] = (unsigned char)(n & 0xff);
    if (is_hs && n >= 4) {
        unsigned long blen = (unsigned long)n - 4;

        rec[5] = 1; /* SSL3_MT_CLIENT_HELLO */
        rec[6] = (unsigned char)((blen >> 16) & 0xff);
        rec[7] = (unsigned char)((blen >> 8) & 0xff);
        rec[8] = (unsigned char)(blen & 0xff);
    }

    ctx = SSL_CTX_new(TLS_method());
    if (ctx == NULL)
        goto done;
    (void)SSL_CTX_use_certificate_chain_file(ctx, CERT_FILE);
    (void)SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM);
    (void)SSL_CTX_check_private_key(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    ERR_clear_error();

    ssl = SSL_new(ctx);
    rbio = BIO_new_mem_buf(rec, (int)total);
    wbio = BIO_new(BIO_s_mem());
    if (ssl == NULL || rbio == NULL || wbio == NULL)
        goto done;
    SSL_set_bio(ssl, rbio, wbio);
    rbio_keep = rbio;
    rbio = wbio = NULL; /* owned by `ssl` */

    r->ret = SSL_accept(ssl);
    r->ssl_error = SSL_get_error(ssl, r->ret);
    r->state = (int)SSL_get_state(ssl);
    r->finished = SSL_is_init_finished(ssl);

    pending = BIO_ctrl(rbio_keep, BIO_CTRL_PENDING, 0, NULL);
    r->consumed = total - (pending > 0 ? pending : 0);
    drain_errors(r);

done:
    if (ssl != NULL)
        SSL_free(ssl);
    if (rbio != NULL)
        BIO_free(rbio);
    if (wbio != NULL)
        BIO_free(wbio);
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    free(rec);
}

static unsigned long long vmdata_kb(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    unsigned long long v = 0;

    if (f == NULL)
        return 0;
    while (fgets(line, sizeof line, f) != NULL) {
        if (strncmp(line, "VmData:", 7) == 0) {
            if (sscanf(line + 7, "%llu", &v) != 1)
                v = 0;
            break;
        }
    }
    fclose(f);
    return v;
}

/* K_RLIMIT: the container's own bound injects the failure. */
static int lower_rlimit(struct result *r)
{
    unsigned long long kb = vmdata_kb();
    struct rlimit rl;

    if (kb > 0 && getrlimit(RLIMIT_DATA, &rl) == 0) {
        rlim_t want = (rlim_t)(kb + 8192) * 1024; /* + 8 MiB of headroom */

        if (want < rl.rlim_cur) {
            rl.rlim_cur = want;
            if (setrlimit(RLIMIT_DATA, &rl) == 0) {
                r->rlimit_lowered = 1;
                return 1;
            }
        }
    }
    return 0;
}

static void drive_rlimit(struct result *r)
{
    void *p;

    r->ret = -1000;
    (void)lower_rlimit(r);
    ERR_clear_error();
    p = CRYPTO_malloc(256u * 1024u * 1024u, FILEID, __LINE__);
    r->alloc_null = p == NULL ? 1 : 0;
    if (p != NULL)
        CRYPTO_free(p, FILEID, __LINE__);
    r->ret = r->alloc_null;
    drain_errors(r);
}

/* K_ASN1: the ASN.1 reader's own allocation under the same bound. */
static void drive_asn1(struct result *r)
{
    /* A DER SEQUENCE that declares a 64 MiB content and then stops: the reader's own allocation
     * must fail and be reported, not abort. */
    static const unsigned char huge[] = {
        0x30, 0x84, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const unsigned char *q = huge;
    X509 *x;

    r->ret = -1000;
    (void)lower_rlimit(r);
    ERR_clear_error();
    x = d2i_X509(NULL, &q, (long)sizeof huge);
    r->d2i_null = x == NULL ? 1 : 0;
    r->ret = r->d2i_null;
    if (x != NULL)
        X509_free(x);
    drain_errors(r);
}

/* K_HOOK: a wrapper allocator that fails the chosen CRYPTO allocation. */
static int g_hook_count;
static int g_hook_fail_after = -1;

static void *hook_malloc(size_t n, const char *file, int line)
{
    (void)file;
    (void)line;
    if (g_hook_fail_after >= 0 && g_hook_count++ >= g_hook_fail_after)
        return NULL;
    return malloc(n);
}

static void *hook_realloc(void *p, size_t n, const char *file, int line)
{
    (void)file;
    (void)line;
    if (g_hook_fail_after >= 0 && g_hook_count++ >= g_hook_fail_after)
        return NULL;
    return realloc(p, n);
}

static void hook_free(void *p, const char *file, int line)
{
    (void)file;
    (void)line;
    free(p);
}

static void drive_hook(struct result *r)
{
    int rc;

    r->ret = -1000;
    r->alloc_set_rc = -1;
    g_hook_count = 0;
    g_hook_fail_after = -1;
    ERR_clear_error();
    rc = CRYPTO_set_mem_functions(hook_malloc, hook_realloc, hook_free);
    r->alloc_set_rc = rc;
    if (rc == 1) {
        SSL_CTX *ctx;

        g_hook_fail_after = 4;
        ERR_clear_error();
        ctx = SSL_CTX_new(TLS_method());
        r->ret = ctx != NULL ? 1 : 0;
        g_hook_fail_after = -1;
        if (ctx != NULL)
            SSL_CTX_free(ctx);
        drain_errors(r);
    }
}

static void drive(const struct kase *k, struct result *r)
{
    memset(r, 0, sizeof *r);
    r->ret = -1000;
    r->bytes = -1;
    r->consumed = -1;
    r->match = -1;
    switch (k->kind) {
    case K_WRITE:
        drive_write(k->n, r);
        break;
    case K_READ_HS:
        drive_read(k->n, 1, r);
        break;
    case K_READ_BODY:
        drive_read(k->n, 0, r);
        break;
    case K_RLIMIT:
        drive_rlimit(r);
        break;
    case K_ASN1:
        drive_asn1(r);
        break;
    case K_HOOK:
        drive_hook(r);
        break;
    default:
        break;
    }
    r->reported = 1;
}

/* One fixed-schema block per case. */
static void emit(const struct kase *k, const char *cls, int signum, const struct result *r)
{
    char key[128];

#define EMIT_INT(field, value) do { \
        snprintf(key, sizeof key, "case.%s." field, k->id); \
        out_int(key, (long)(value)); \
    } while (0)
#define EMIT_STR(field, value) do { \
        snprintf(key, sizeof key, "case.%s." field, k->id); \
        out_str(key, (value)); \
    } while (0)

    EMIT_STR("class", cls);
    EMIT_STR("path", k->path);
    EMIT_STR("phase", k->phase);
    EMIT_INT("capacity", k->capacity);
    EMIT_INT("request", k->n);
    EMIT_INT("signal", signum);
    EMIT_INT("ret", r->ret);
    EMIT_INT("ssl_error", r->ssl_error);
    EMIT_INT("state", r->state);
    EMIT_INT("finished", r->finished);
    EMIT_INT("err_count", r->err_count);
    EMIT_INT("reason0", r->reason0);
    EMIT_INT("bytes", r->bytes);
    EMIT_INT("consumed", r->consumed);
    EMIT_INT("match", r->match);
    EMIT_INT("alloc_null", r->alloc_null);
    EMIT_INT("alloc_malloc_failure", r->alloc_malloc_failure);
    EMIT_INT("d2i_null", r->d2i_null);
    EMIT_INT("rlimit_lowered", r->rlimit_lowered);
    EMIT_INT("alloc_set_rc", r->alloc_set_rc);

#undef EMIT_INT
#undef EMIT_STR
}

int main(void)
{
    int i;

    setvbuf(stdout, NULL, _IOLBF, 0);

    out_int("cases.count", N_CASES);

    for (i = 0; i < N_CASES; i++) {
        const struct kase *k = &CASES[i];
        int pipefd[2];
        pid_t pid;
        struct result r;
        int class_timeout = 0;
        int status = 0;
        struct timespec t0;

        memset(&r, 0, sizeof r);
        r.ret = -1000;
        r.bytes = -1;
        r.consumed = -1;
        r.match = -1;
        r.alloc_set_rc = -1;

        if (pipe(pipefd) != 0) {
            emit(k, "probe-error", 0, &r);
            continue;
        }
        pid = fork();
        if (pid < 0) {
            close(pipefd[0]);
            close(pipefd[1]);
            emit(k, "probe-error", 0, &r);
            continue;
        }
        if (pid == 0) {
            struct result cr;
            const char *src;
            ssize_t off = 0;

            close(pipefd[0]);
            drive(k, &cr);
            src = (const char *)&cr;
            while (off < (ssize_t)sizeof cr) {
                ssize_t w = write(pipefd[1], src + off, sizeof cr - (size_t)off);

                if (w <= 0)
                    break;
                off += w;
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
            if (elapsed_ms > CASE_TIMEOUT_MS) {
                class_timeout = 1;
                kill(pid, SIGKILL);
                while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
                    ;
                break;
            }
            {
                struct timespec s = {0, 2000000}; /* 2 ms */

                nanosleep(&s, NULL);
            }
        }
        {
            ssize_t got = 0;
            char *dst = (char *)&r;

            while (got < (ssize_t)sizeof r) {
                ssize_t rd = read(pipefd[0], dst + got, sizeof r - (size_t)got);

                if (rd > 0) {
                    got += rd;
                    continue;
                }
                break;
            }
        }
        close(pipefd[0]);

        if (class_timeout)
            emit(k, "timeout", 0, &r);
        else if (WIFSIGNALED(status))
            emit(k, "crash", WTERMSIG(status), &r);
        else if (WIFEXITED(status) && WEXITSTATUS(status) == CHILD_OOM)
            emit(k, "oom", 0, &r);
        else if (WIFEXITED(status))
            emit(k, "ran", 0, &r);
        else
            emit(k, "probe-error", 0, &r);
    }

    printf("probe.done=1\n");
    return 0;
}
