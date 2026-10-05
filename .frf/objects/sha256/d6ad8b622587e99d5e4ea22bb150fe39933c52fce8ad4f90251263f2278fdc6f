/*
 * RT-HOSTILE-TLS - the Phase 18 hostile TLS corpus, driven through the record layer and the
 * TLS 1.3 flight, with per-entry crash / OOM / timeout detection.
 *
 * What it drives
 * --------------
 * `courts/phase18/fixtures/hostile-tls/` holds one file per corpus entry, named
 * `<role>__<id>.bin`. Each entry is fed to the side that *receives* it: a `server` entry is
 * written into the read side of an `SSL` in `SSL_accept` (so the ClientHello / record reader
 * parses it) and a `client` entry into an `SSL` in `SSL_connect` (so the ServerHello / flight
 * reader parses it). The read side is a `BIO_new_mem_buf`, which reports EOF once the bytes are
 * consumed, so a truncated message is seen as a truncation rather than a retryable read.
 *
 * One entry per process, because a hostile input may not terminate
 * -----------------------------------------------------------------
 * Section 3.3 of `docs/PHASE-18-SUBPHASES.md`: a crash, an exhausted allocation budget or a
 * failure to terminate is a *recorded finding* for that entry, not a harness abort. So the probe
 * forks once per entry. A child killed by a signal is a `crash`; a child that reports an
 * allocation failure under the process's own `RLIMIT_DATA` is an `oom`; a child that does not
 * finish inside `ENTRY_TIMEOUT_MS` is killed and recorded `timeout`. The parent's own exit status
 * is always 0, so a crashing input cannot take the court down with it.
 *
 * The transcript is a property of the library
 * -------------------------------------------
 * The parent prints one fixed-schema `key=value` block per entry, whether the child reported a
 * disposition, crashed, or timed out, so the two sides' observation counts always agree and a
 * missing entry can never read as a shorter, silent transcript. Nothing printed is derived from
 * the probe's own frame, the clock, an address or a random field: only the library's return
 * values (`SSL_accept`/`SSL_connect`, `SSL_get_error`, `SSL_get_state`, `SSL_is_init_finished`,
 * the `ERR` queue and the alert callback) and the byte counts of what the handshake wrote.
 *
 * It is compiled twice, once against the admitted authority's prefix and once against the
 * candidate distribution shell, and the two transcripts are diffed. It is NOT a memory-safety or
 * security proof: it is a bounded differential result over the corpus it drives (section 3.1).
 *
 * argv: [corpus-dir]   (default /work/courts/phase18/fixtures/hostile-tls)
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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define DEFAULT_CORPUS "/work/courts/phase18/fixtures/hostile-tls"
#define CERT_FILE "/work/courts/phase17/fixtures/signer.pem"
#define KEY_FILE "/work/courts/phase17/fixtures/rsa-key.pem"

#define ENTRY_TIMEOUT_MS 4000
#define CHILD_OOM 42
#define MAX_ENTRIES 512
#define MAX_NAME 256

/* A child's disposition, written to the parent over a pipe in one atomic write. */
struct result {
    int reported;
    int oom;
    int ret;
    int ssl_error;
    int err_count;
    int reason0;
    int state;
    int finished;
    long out_bytes;
    int out_first;
    char alert[80];
};

struct entry {
    char name[MAX_NAME];
    char id[MAX_NAME];
    int is_client;
};

static char g_alert[80];

static const char *ALERT_UNSET = "-";

static void info_cb(const SSL *s, int where, int ret)
{
    (void)s;
    if ((where & SSL_CB_ALERT) != 0) {
        const char *d = SSL_alert_desc_string_long(ret);

        if (d != NULL)
            snprintf(g_alert, sizeof g_alert, "%s", d);
    }
}

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_str(const char *key, const char *v)
{
    printf("%s=%s\n", key, v != NULL ? v : "");
}

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
    if (n < 0) {
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
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

/* Fill `r` with the disposition of driving `path`. */
static void drive(const char *path, int is_client, struct result *r)
{
    unsigned char *buf = NULL;
    long n = 0;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *rbio = NULL, *wbio = NULL;
    int ret, err, i;
    unsigned long e;
    char *p = NULL;
    long outn;

    memset(r, 0, sizeof *r);
    r->ret = -1000;
    r->out_first = -1;
    snprintf(r->alert, sizeof r->alert, "%s", ALERT_UNSET);
    snprintf(g_alert, sizeof g_alert, "%s", ALERT_UNSET);

    if (read_file(path, &buf, &n) != 0) {
        r->reported = 1;
        return;
    }

    ctx = SSL_CTX_new(TLS_method());
    if (ctx == NULL) {
        free(buf);
        r->reported = 1;
        return;
    }
    if (!is_client) {
        (void)SSL_CTX_use_certificate_chain_file(ctx, CERT_FILE);
        (void)SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM);
        (void)SSL_CTX_check_private_key(ctx);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_info_callback(ctx, info_cb);
    ERR_clear_error();

    ssl = SSL_new(ctx);
    rbio = BIO_new_mem_buf(buf, (int)n);
    wbio = BIO_new(BIO_s_mem());
    if (ssl == NULL || rbio == NULL || wbio == NULL) {
        r->reported = 1;
        goto done;
    }
    SSL_set_bio(ssl, rbio, wbio);

    if (is_client)
        ret = SSL_connect(ssl);
    else
        ret = SSL_accept(ssl);
    err = SSL_get_error(ssl, ret);
    r->ret = ret;
    r->ssl_error = err;
    r->state = (int)SSL_get_state(ssl);
    r->finished = SSL_is_init_finished(ssl);

    /* Drain up to four errors, recording the first reason. This is also the OOM detector: a
     * failed allocation inside the library raises ERR_R_MALLOC_FAILURE, which the process's own
     * RLIMIT_DATA (and the container's cgroup cap) is what can actually cause. */
    for (i = 0; i < 4 && (e = ERR_get_error()) != 0; i++) {
        if (i == 0)
            r->reason0 = (int)ERR_GET_REASON(e);
        if ((int)ERR_GET_REASON(e) == ERR_R_MALLOC_FAILURE)
            r->oom = 1;
    }
    r->err_count = i;

    outn = BIO_get_mem_data(wbio, &p);
    r->out_bytes = outn > 0 ? outn : 0;
    if (outn > 5 && p != NULL)
        r->out_first = (unsigned char)p[5];

done:
    snprintf(r->alert, sizeof r->alert, "%s", g_alert);
    if (ssl != NULL)
        SSL_free(ssl);
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    free(buf);
    r->reported = 1;
}

/* Parse role__id.bin; return 0 on success. */
static int parse_name(const char *filename, struct entry *e)
{
    const char *sep;
    size_t len = strlen(filename);

    if (len < 5 || strcmp(filename + len - 4, ".bin") != 0)
        return -1;
    if (strncmp(filename, "client__", 8) == 0)
        e->is_client = 1;
    else if (strncmp(filename, "server__", 8) == 0)
        e->is_client = 0;
    else
        return -1;
    sep = strstr(filename, "__");
    if (sep == NULL)
        return -1;
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
    EMIT_STR("role", e->is_client ? "client" : "server");
    EMIT_INT("signal", signum);
    EMIT_INT("ret", r->ret);
    EMIT_INT("ssl_error", r->ssl_error);
    EMIT_INT("err_count", r->err_count);
    EMIT_INT("reason0", r->reason0);
    EMIT_INT("state", r->state);
    EMIT_INT("finished", r->finished);
    EMIT_INT("out_bytes", r->out_bytes);
    EMIT_INT("out_first", r->out_first);
    EMIT_STR("alert", r->alert);

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
        fprintf(stderr, "hostile-tls: cannot open corpus %s: %s\n", dir, strerror(errno));
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
        r.out_first = -1;
        snprintf(r.alert, sizeof r.alert, "%s", ALERT_UNSET);

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
            drive(path, entries[i].is_client, &cr);
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
        /* The child writes the struct once, atomically, before exiting. A crash writes nothing,
         * so the parent's defaults stand. */
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
