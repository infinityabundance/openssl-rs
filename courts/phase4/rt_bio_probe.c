/*
 * openssl-rs — Phase 4 court: BIO, differentially.
 *
 * Compiled twice (authority headers + authority libcrypto, candidate headers +
 * candidate libcrypto) and run; the two transcripts are compared line by line,
 * keyed on `key=value`. Every line is an observation of the authority, not an
 * expectation written down by hand, so the probe cannot drift away from what the
 * authority does without the court noticing.
 *
 * Only symbols the candidate *implements* are touched. A scaffolded symbol
 * aborts the candidate with a diagnostic, which would turn this court into a
 * "not implemented yet" report rather than a behavioural comparison; the
 * obligation ledger is the artefact that records what is not built.
 *
 * Nothing in the transcript is a pointer, an address, or an allocation count:
 * those vary between two builds of the same program and would be residual noise.
 * They are printed to stderr, which is captured for a human debugging a failure
 * but never diffed.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#define OUT(...) fprintf(stdout, __VA_ARGS__)

/* Drain everything currently in a memory BIO into `dst`; returns its length. */
static size_t drain_mem(BIO *b, char *dst, size_t cap)
{
    int n = BIO_read(b, dst, (int)(cap - 1));
    if (n < 0)
        n = 0;
    dst[n] = '\0';
    return (size_t)n;
}

static int callback_events = 0;
static char callback_log[256];

static long cb_ex(BIO *b, int oper, const char *argp, size_t len, int argi,
                  long argl, int ret, size_t *processed)
{
    (void)b; (void)argp; (void)argl; (void)processed; (void)len; (void)argi;
    if (callback_events < 200)
        callback_log[callback_events++] = (char)('a' + (oper & 0x1f));
    return (oper & BIO_CB_RETURN) ? ret : 1;
}

static void section(const char *name)
{
    OUT("\n# %s\n", name);
}

int main(void)
{
    /* Line-buffered so that, if a probe hits an authority fault, the last
     * completed observation is still in the transcript and names the call. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    char buf[512];
    char *ptr;
    BUF_MEM *bm;
    size_t sz = 0;
    long v;
    int i;

    /* ---------------------------------------------------------------- */
    section("method-identity");

    /* `BIO_method_name`/`BIO_method_type` take a BIO, not a method table, so the
     * identity of each built-in method is observed through an instance. */
    BIO *t = BIO_new(BIO_s_mem());
    OUT("mem.name=%s\n", BIO_method_name(t));
    OUT("mem.type=%d\n", BIO_method_type(t));
    BIO_free(t);
    t = BIO_new(BIO_s_secmem());
    OUT("secmem.name=%s\n", BIO_method_name(t));
    OUT("secmem.type=%d\n", BIO_method_type(t));
    BIO_free(t);
    t = BIO_new(BIO_s_null());
    OUT("null.name=%s\n", BIO_method_name(t));
    OUT("null.type=%d\n", BIO_method_type(t));
    BIO_free(t);
    t = BIO_new(BIO_f_null());
    OUT("fnull.name=%s\n", BIO_method_name(t));
    OUT("fnull.type=%d\n", BIO_method_type(t));
    BIO_free(t);
    t = BIO_new(BIO_s_socket());
    OUT("socket.name=%s\n", BIO_method_name(t));
    OUT("socket.type=%d\n", BIO_method_type(t));
    /* A freshly created socket BIO has init=1 and num=0, and its destructor
     * closes `num` when shutdown is set -- so this pair is also an observation of
     * whether descriptor 0 survives. */
    OUT("socket.new.num=%ld\n", BIO_ctrl(t, BIO_C_GET_FD, 0, (void *)(int[1]){ 0 }));
    BIO_free(t);
    OUT("fd0.after_socket_identity=%d\n", fcntl(0, F_GETFD) != -1);

    /* ---------------------------------------------------------------- */
    section("lifecycle");

    BIO *m = BIO_new(BIO_s_mem());
    OUT("new.nonnull=%d\n", m != NULL);
    OUT("new.init=%d\n", BIO_get_init(m));
    OUT("new.shutdown=%d\n", BIO_get_shutdown(m));
    OUT("new.method=%s\n", BIO_method_name(m));
    OUT("new.num_read=%llu\n", (unsigned long long)BIO_number_read(m));
    OUT("new.num_written=%llu\n", (unsigned long long)BIO_number_written(m));

    OUT("up_ref=%d\n", BIO_up_ref(m));
    OUT("free.one=%d\n", BIO_free(m));
    OUT("free.two=%d\n", BIO_free(m));

    /* A method with no create is initialised by BIO_new itself. */
    BIO *n = BIO_new(BIO_s_null());
    OUT("null.new.init=%d\n", BIO_get_init(n));
    OUT("null.new.shutdown=%d\n", BIO_get_shutdown(n));
    BIO_free(n);

    /* ---------------------------------------------------------------- */
    section("memory-write-read");

    m = BIO_new(BIO_s_mem());
    OUT("write=%d\n", BIO_write(m, "hello world", 11));
    OUT("write.ex=%d\n", BIO_write_ex(m, "!!", 2, &sz));
    OUT("write.ex.n=%d\n", (int)sz);
    OUT("pending=%d\n", (int)BIO_ctrl_pending(m));
    OUT("wpending=%d\n", (int)BIO_ctrl_wpending(m));
    OUT("num_written=%llu\n", (unsigned long long)BIO_number_written(m));

    /* The two read entry points have different contracts. */
    memset(buf, 0, sizeof(buf));
    OUT("read.5=%d\n", BIO_read(m, buf, 5));
    OUT("read.5.bytes=%s\n", buf);
    sz = 0;
    OUT("read.ex.3=%d\n", BIO_read_ex(m, buf, 3, &sz));
    OUT("read.ex.3.n=%d\n", (int)sz);
    buf[sz] = '\0';
    OUT("read.ex.3.bytes=%s\n", buf);
    OUT("pending.after=%d\n", (int)BIO_ctrl_pending(m));
    OUT("num_read=%llu\n", (unsigned long long)BIO_number_read(m));

    OUT("read.rest=%d\n", BIO_read(m, buf, 100));
    buf[8] = '\0';
    OUT("read.rest.bytes=%s\n", buf);

    /* Empty buffer: eof_return defaults to -1 and sets the retry-read flag. */
    OUT("read.empty=%d\n", BIO_read(m, buf, 16));
    OUT("read.empty.should_retry=%d\n", BIO_should_retry(m));
    OUT("read.empty.should_read=%d\n", BIO_should_read(m));
    BIO_clear_flags(m, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_READ);

    /* Setting eof_return to 0 suppresses the retry flag. */
    OUT("set.eof_return=%ld\n", BIO_ctrl(m, BIO_C_SET_BUF_MEM_EOF_RETURN, 0, NULL));
    OUT("read.empty0=%d\n", BIO_read(m, buf, 16));
    OUT("read.empty0.should_retry=%d\n", BIO_should_retry(m));

    OUT("eof=%ld\n", BIO_ctrl(m, BIO_CTRL_EOF, 0, NULL));
    OUT("info.len=%ld\n", BIO_ctrl(m, BIO_CTRL_INFO, 0, &ptr));
    OUT("pending.macro=%d\n", (int)BIO_ctrl_pending(m));
    BIO_free(m);

    /* ---------------------------------------------------------------- */
    section("memory-gets-seek-reset");

    m = BIO_new(BIO_s_mem());
    BIO_write(m, "one\ntwo\nthree", 13);

    OUT("gets=%d\n", BIO_gets(m, buf, sizeof(buf)));
    OUT("gets.line=%s", buf);
    OUT("gets.again=%d\n", BIO_gets(m, buf, sizeof(buf)));
    OUT("gets.again.line=%s", buf);

    OUT("tell=%ld\n", BIO_ctrl(m, BIO_C_FILE_TELL, 0, NULL));
    OUT("seek.0=%ld\n", BIO_ctrl(m, BIO_C_FILE_SEEK, 0, NULL));
    OUT("tell.after_seek=%ld\n", BIO_ctrl(m, BIO_C_FILE_TELL, 0, NULL));
    OUT("seek.past_end=%ld\n", BIO_ctrl(m, BIO_C_FILE_SEEK, 1000, NULL));
    OUT("seek.negative=%ld\n", BIO_ctrl(m, BIO_C_FILE_SEEK, -1, NULL));

    OUT("reset=%ld\n", BIO_ctrl(m, BIO_CTRL_RESET, 0, NULL));
    OUT("pending.after_reset=%d\n", (int)BIO_ctrl_pending(m));

    /* get_mem_ptr exposes the BUF_MEM, whose growth policy is observable. */
    BIO_write(m, "0123456789", 10);
    OUT("get_mem_ptr=%ld\n", BIO_ctrl(m, BIO_C_GET_BUF_MEM_PTR, 0, (char *)&bm));
    OUT("mem.length=%zu\n", bm->length);
    OUT("mem.max=%zu\n", bm->max);
    BIO_write(m, "abcdefghijklmnopqrstuvwxyz", 26);
    OUT("get_mem_ptr2=%ld\n", BIO_ctrl(m, BIO_C_GET_BUF_MEM_PTR, 0, (char *)&bm));
    OUT("mem2.length=%zu\n", bm->length);
    OUT("mem2.max=%zu\n", bm->max);
    BIO_free(m);

    /* ---------------------------------------------------------------- */
    section("read-only-memory");

    BIO *ro = BIO_new_mem_buf("abcdef", 6);
    OUT("ro.init=%d\n", BIO_get_init(ro));
    memset(buf, 0, sizeof(buf));
    OUT("ro.read=%d\n", BIO_read(ro, buf, 6));
    OUT("ro.bytes=%s\n", buf);
    OUT("ro.eofread=%d\n", BIO_read(ro, buf, 6));
    ERR_clear_error();
    OUT("ro.write=%d\n", BIO_write(ro, "x", 1));
    OUT("ro.err.lib=%d\n", ERR_GET_LIB(ERR_peek_error()));
    OUT("ro.err.reason=%d\n", ERR_GET_REASON(ERR_peek_error()));
    BIO_free(ro);

    /* ---------------------------------------------------------------- */
    section("chains");

    BIO *a = BIO_new(BIO_s_mem());
    BIO *b = BIO_new(BIO_f_null());
    BIO *c = BIO_new(BIO_s_null());
    OUT("push.head=%d\n", BIO_push(b, a) == b);
    OUT("push.head2=%d\n", BIO_push(c, b) == c);
    OUT("next.c=%d\n", BIO_next(c) == b);
    OUT("next.b=%d\n", BIO_next(b) == a);
    OUT("next.a.null=%d\n", BIO_next(a) == NULL);
    OUT("find.mem=%d\n", BIO_find_type(c, BIO_TYPE_MEM) == a);
    OUT("find.filter=%d\n", BIO_find_type(c, BIO_TYPE_FILTER) == b);
    OUT("find.null=%d\n", BIO_find_type(c, BIO_TYPE_NULL) == c);
    OUT("find.bad=%d\n", BIO_find_type(c, 0x7fff) == NULL);

    /* A filter forwards, so a write at the head reaches the memory BIO. */
    OUT("chain.write=%d\n", BIO_write(c, "xyz", 3));
    OUT("chain.pending=%d\n", (int)BIO_ctrl_pending(a));

    OUT("pop.c.ret=%d\n", BIO_pop(c) == b);
    OUT("pop.c.next_is_null=%d\n", BIO_next(c) == NULL);
    BIO_free(c);
    BIO_free_all(b);

    /* ---------------------------------------------------------------- */
    section("dup-chain");

    BIO *src = BIO_new(BIO_s_mem());
    BIO_write(src, "dup", 3);
    BIO_set_flags(src, BIO_FLAGS_NONCLEAR_RST);
    BIO *dup = BIO_dup_chain(src);
    OUT("dup.nonnull=%d\n", dup != NULL);
    OUT("dup.method=%s\n", BIO_method_name(dup));
    OUT("dup.next_null=%d\n", BIO_next(dup) == NULL);
    OUT("dup.flags=%d\n", BIO_test_flags(dup, BIO_FLAGS_NONCLEAR_RST) != 0);
    /* The copy shares no state with the original. */
    OUT("src.pending=%d\n", (int)BIO_ctrl_pending(src));
    OUT("dup.pending=%d\n", (int)BIO_ctrl_pending(dup));
    OUT("dup.read=%d\n", BIO_read(dup, buf, 8));
    buf[3] = '\0';
    OUT("dup.bytes=%s\n", buf);
    OUT("src.pending.after=%d\n", (int)BIO_ctrl_pending(src));
    BIO_free(dup);
    BIO_free(src);

    /* ---------------------------------------------------------------- */
    section("callbacks");

    m = BIO_new(BIO_s_mem());
    BIO_set_callback_ex(m, cb_ex);
    callback_events = 0;
    callback_log[0] = '\0';
    BIO_write(m, "cb", 2);
    BIO_read(m, buf, 2);
    BIO_ctrl(m, BIO_CTRL_RESET, 0, NULL);
    OUT("cb.log=%s\n", callback_log);
    BIO_set_callback_ex(m, NULL);

    BIO_set_callback(m, BIO_debug_callback);
    OUT("cb.legacy.set=%d\n", BIO_get_callback(m) == BIO_debug_callback);
    BIO_set_callback(m, NULL);
    OUT("cb.legacy.cleared=%d\n", BIO_get_callback(m) == NULL);
    BIO_free(m);

    /* ---------------------------------------------------------------- */
    section("flags-and-retry");

    m = BIO_new(BIO_s_mem());
    OUT("flags.initial=%d\n", BIO_test_flags(m, ~0));
    BIO_set_flags(m, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY);
    OUT("flags.set=%d\n", BIO_test_flags(m, ~0));
    OUT("should_read=%d\n", BIO_should_read(m));
    OUT("retry_type=%d\n", BIO_retry_type(m));
    BIO_set_retry_reason(m, BIO_RR_CONNECT);
    OUT("retry_reason=%d\n", BIO_get_retry_reason(m));
    OUT("retry_bio.self=%d\n", BIO_get_retry_BIO(m, &i) == m);
    OUT("retry_bio.reason=%d\n", i);
    BIO_clear_flags(m, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY);
    OUT("flags.cleared=%d\n", BIO_test_flags(m, ~0));
    BIO_free(m);

    /* ---------------------------------------------------------------- */
    section("misc-control");

    m = BIO_new(BIO_s_mem());
    OUT("ctrl.null_bio=%ld\n", BIO_ctrl(NULL, BIO_CTRL_RESET, 0, NULL));
    OUT("ctrl.set_close=%ld\n", BIO_ctrl(m, BIO_CTRL_SET_CLOSE, 1, NULL));
    OUT("ctrl.get_close=%ld\n", BIO_ctrl(m, BIO_CTRL_GET_CLOSE, 0, NULL));
    OUT("ctrl.unknown=%ld\n", BIO_ctrl(m, 9999, 0, NULL));
    OUT("ctrl.flush=%ld\n", BIO_ctrl(m, BIO_CTRL_FLUSH, 0, NULL));
    OUT("ctrl.dup=%ld\n", BIO_ctrl(m, BIO_CTRL_DUP, 0, NULL));
    OUT("callback_ctrl.bad_cmd=%ld\n", BIO_callback_ctrl(m, 999, NULL));
    OUT("int_ctrl=%ld\n", BIO_int_ctrl(m, BIO_C_SET_BUF_MEM_EOF_RETURN, 0, 7));
    OUT("ptr_ctrl.null=%d\n", BIO_ptr_ctrl(m, 9999, 0) == NULL);
    BIO_vfree(m);

    /* A method with no ctrl at all reports -2 and raises. */
    BIO_METHOD *meth = BIO_meth_new(129, "no-ctrl");
    BIO *plain = BIO_new(meth);
    ERR_clear_error();
    OUT("ctrl.unsupported=%ld\n", BIO_ctrl(plain, BIO_CTRL_RESET, 0, NULL));
    OUT("ctrl.unsupported.reason=%d\n", ERR_GET_REASON(ERR_peek_error()));
    OUT("plain.init=%d\n", BIO_get_init(plain));
    BIO_free(plain);
    BIO_meth_free(meth);

    /* ---------------------------------------------------------------- */
    section("method-api");

    BIO_METHOD *mm = BIO_meth_new(200, "custom");
    OUT("meth.name_null=%d\n", BIO_meth_new(200, NULL) == NULL);
    OUT("meth.get_read.initial=%d\n", BIO_meth_get_read(mm) == NULL);
    OUT("meth.get_read_ex.initial=%d\n", BIO_meth_get_read_ex(mm) == NULL);
    OUT("meth.get_write.initial=%d\n", BIO_meth_get_write(mm) == NULL);
    OUT("meth.get_write_ex.initial=%d\n", BIO_meth_get_write_ex(mm) == NULL);
    OUT("meth.set_read=%d\n", BIO_meth_set_read(mm, BIO_gets));
    /* The dispatch slot is populated by the conversion shim, not by the legacy
     * pointer, so the _ex getter is non-NULL after either setter. */
    OUT("meth.get_read.after_legacy=%d\n", BIO_meth_get_read(mm) != NULL);
    OUT("meth.get_read_ex.after_legacy=%d\n", BIO_meth_get_read_ex(mm) != NULL);
    OUT("meth.get_read_ex.same=%d\n", BIO_meth_get_read_ex(mm) != NULL);
    OUT("meth.set_read_ex=%d\n", BIO_meth_set_read_ex(mm, NULL));
    OUT("meth.get_read.after_ex=%d\n", BIO_meth_get_read(mm) == NULL);
    OUT("meth.get_read_ex.after_ex=%d\n", BIO_meth_get_read_ex(mm) == NULL);
    OUT("meth.set_ctrl=%d\n", BIO_meth_set_ctrl(mm, NULL));
    OUT("meth.get_ctrl=%d\n", BIO_meth_get_ctrl(mm) == NULL);
    OUT("meth.set_create=%d\n", BIO_meth_set_create(mm, NULL));
    OUT("meth.get_create=%d\n", BIO_meth_get_create(mm) == NULL);
    OUT("meth.set_destroy=%d\n", BIO_meth_set_destroy(mm, NULL));
    OUT("meth.get_destroy=%d\n", BIO_meth_get_destroy(mm) == NULL);
    OUT("meth.set_callback_ctrl=%d\n", BIO_meth_set_callback_ctrl(mm, NULL));
    OUT("meth.get_callback_ctrl=%d\n", BIO_meth_get_callback_ctrl(mm) == NULL);
    OUT("meth.set_puts=%d\n", BIO_meth_set_puts(mm, NULL));
    OUT("meth.get_puts=%d\n", BIO_meth_get_puts(mm) == NULL);
    BIO_meth_free(mm);

    v = BIO_get_new_index();
    OUT("new_index.first_delta=%ld\n", v - 128);
    v = BIO_get_new_index();
    OUT("new_index.second_delta=%ld\n", v - 128);

    /* ---------------------------------------------------------------- */
    section("printf-and-dump");

    m = BIO_new(BIO_s_mem());
    OUT("printf.ret=%d\n", BIO_printf(m, "%s=%d", "n", 42));
    drain_mem(m, buf, sizeof(buf));
    OUT("printf.out=%s\n", buf);

    OUT("snprintf.ret=%d\n", BIO_snprintf(buf, sizeof(buf), "%04x-%s", 255, "z"));
    OUT("snprintf.out=%s\n", buf);
    OUT("snprintf.trunc=%d\n", BIO_snprintf(buf, 4, "%s", "abcdef"));
    OUT("snprintf.trunc.out=%s\n", buf);

    OUT("indent=%d\n", BIO_indent(m, 3, 10));
    drain_mem(m, buf, sizeof(buf));
    OUT("indent.out=[%s]\n", buf);
    OUT("indent.clamped=%d\n", BIO_indent(m, 99, 2));
    drain_mem(m, buf, sizeof(buf));
    OUT("indent.clamped.out=[%s]\n", buf);
    BIO_free(m);

    /* A dump of a known 20-byte buffer, full width and indented. */
    static const unsigned char data[20] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0xf8, 0xf9, 0x61, 0x62, 0x20, 0x7e, 0x7f, 0x0a,
        0x80, 0xff, 0x41, 0x42,
    };
    m = BIO_new(BIO_s_mem());
    OUT("dump.ret=%d\n", BIO_dump(m, data, (int)sizeof(data)));
    drain_mem(m, buf, sizeof(buf));
    OUT("dump.out=%s", buf);
    BIO_free(m);

    m = BIO_new(BIO_s_mem());
    OUT("dump.indent.ret=%d\n", BIO_dump_indent(m, data, (int)sizeof(data), 8));
    drain_mem(m, buf, sizeof(buf));
    OUT("dump.indent.out=%s", buf);
    BIO_free(m);

    m = BIO_new(BIO_s_mem());
    OUT("dump.short.ret=%d\n", BIO_dump(m, data, 3));
    drain_mem(m, buf, sizeof(buf));
    OUT("dump.short.out=%s", buf);
    BIO_free(m);

    m = BIO_new(BIO_s_mem());
    OUT("hex.ret=%d\n", BIO_hex_string(m, 4, 8, data, 20));
    drain_mem(m, buf, sizeof(buf));
    OUT("hex.out=%s\n", buf);
    BIO_free(m);

    /* ---------------------------------------------------------------- */
    section("buffer-object");

    BUF_MEM *b1 = BUF_MEM_new();
    OUT("bufmem.new=%d\n", b1 != NULL);
    OUT("bufmem.length=%zu\n", b1->length);
    OUT("bufmem.max=%zu\n", b1->max);
    OUT("bufmem.grow10=%zu\n", BUF_MEM_grow(b1, 10));
    OUT("bufmem.max10=%zu\n", b1->max);
    OUT("bufmem.length10=%zu\n", b1->length);
    OUT("bufmem.grow100=%zu\n", BUF_MEM_grow(b1, 100));
    OUT("bufmem.max100=%zu\n", b1->max);
    OUT("bufmem.shrink=%zu\n", BUF_MEM_grow(b1, 5));
    OUT("bufmem.length5=%zu\n", b1->length);
    OUT("bufmem.grow_clean=%zu\n", BUF_MEM_grow_clean(b1, 200));
    OUT("bufmem.max_clean=%zu\n", b1->max);
    BUF_MEM_free(b1);

    BUF_MEM *b2 = BUF_MEM_new_ex(BUF_MEM_FLAG_SECURE);
    OUT("bufmem.secure.flags=%lu\n", b2->flags);
    BUF_MEM_free(b2);

    /* ---------------------------------------------------------------- */
    section("sockets");

    int sp[2];
    OUT("fd0.before_socketpair=%d\n", fcntl(0, F_GETFD) != -1);
    OUT("socketpair=%d\n", socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
    OUT("socketpair.fd0_is_zero=%d\n", sp[0] == 0);

    BIO *s = BIO_new_socket(sp[0], BIO_CLOSE);
    OUT("sock.nonnull=%d\n", s != NULL);
    OUT("sock.method=%s\n", BIO_method_name(s));
    OUT("sock.init=%d\n", BIO_get_init(s));
    i = -1;
    OUT("sock.get_fd.returns_desc=%d\n",
        BIO_ctrl(s, BIO_C_GET_FD, 0, (char *)&i) == sp[0]);
    OUT("sock.get_fd.sets_parg=%d\n", i == sp[0]);
    OUT("sock.get_fd.null_parg=%d\n",
        BIO_ctrl(s, BIO_C_GET_FD, 0, NULL) == sp[0]);
    OUT("sock.write=%d\n", BIO_write(s, "ping", 4));
    memset(buf, 0, sizeof(buf));
    OUT("sock.peer_read=%d\n", (int)read(sp[1], buf, 4));
    OUT("sock.peer_bytes=%s\n", buf);
    OUT("sock.nbio=%d\n", BIO_socket_nbio(sp[0], 1));
    OUT("sock.nbio_get=%ld\n", BIO_ctrl(s, BIO_C_SET_NBIO, 1, NULL));
    BIO_free(s);
    close(sp[1]);

    OUT("sock.non_fatal.EAGAIN=%d\n", BIO_sock_non_fatal_error(EAGAIN));
    OUT("sock.non_fatal.EINTR=%d\n", BIO_sock_non_fatal_error(EINTR));
    OUT("sock.non_fatal.0=%d\n", BIO_sock_non_fatal_error(0));
    OUT("sock.non_fatal.EBADF=%d\n", BIO_sock_non_fatal_error(9));
    OUT("sock.should_retry.-1=%d\n", BIO_sock_should_retry(-1));
    OUT("sock.should_retry.1=%d\n", BIO_sock_should_retry(1));
    OUT("sock.should_retry.0=%d\n", BIO_sock_should_retry(0));
    OUT("sock.err_is_non_fatal.sys=%d\n", BIO_err_is_non_fatal(ERR_LIB_SYS | EAGAIN));
    OUT("sock.err_is_non_fatal.0=%d\n", BIO_err_is_non_fatal(0));
    OUT("sock.init=%d\n", BIO_sock_init());
    OUT("sock.error=%d\n", BIO_sock_error(-1));

    /* A wait on a ready descriptor returns at once. */
    int sp2[2];
    (void)socketpair(AF_UNIX, SOCK_STREAM, 0, sp2);
    OUT("wait.ready.n=%d\n", (int)write(sp2[0], "x", 1));
    OUT("wait.ready=%d\n", BIO_socket_wait(sp2[1], 1, (long)time(NULL) + 2));
    close(sp2[0]);
    close(sp2[1]);

    /* ---------------------------------------------------------------- */
    section("ex-data-and-data");

    /* `ex_data` lives beside the method's private pointer, so it is exercised on
     * a memory BIO. The generic data/init/shutdown/next slots are exercised on a
     * null BIO, because `BIO_set_data` overwrites the method's own `ptr` — doing
     * that on a memory BIO would replace the buffer header the destructor then
     * frees, which is a probe error, not an authority behaviour. */
    m = BIO_new(BIO_s_mem());
    int idx = BIO_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    OUT("exdata.index=%d\n", idx);
    OUT("exdata.set=%d\n", BIO_set_ex_data(m, idx, (void *)&m));
    OUT("exdata.get=%d\n", BIO_get_ex_data(m, idx) == (void *)&m);
    OUT("exdata.missing=%d\n", BIO_get_ex_data(m, idx + 1) == NULL);
    BIO_free(m);

    BIO *g = BIO_new(BIO_s_null());
    BIO_set_data(g, (void *)&v);
    OUT("data.get=%d\n", BIO_get_data(g) == (void *)&v);
    BIO_set_flags(g, BIO_FLAGS_NONCLEAR_RST);
    OUT("set.flags.roundtrip=%d\n", BIO_test_flags(g, BIO_FLAGS_NONCLEAR_RST) != 0);
    BIO_set_init(g, 0);
    OUT("set.init=%d\n", BIO_get_init(g));
    BIO_set_shutdown(g, 0);
    OUT("set.shutdown=%d\n", BIO_get_shutdown(g));
    BIO_set_next(g, NULL);
    OUT("set.next=%d\n", BIO_next(g) == NULL);
    BIO_set_callback_arg(g, buf);
    OUT("cb_arg=%d\n", BIO_get_callback_arg(g) == buf);
    BIO_free(g);

    /* A get_line over a memory BIO. */
    m = BIO_new_mem_buf("alpha\nbeta", -1);
    memset(buf, 0, sizeof(buf));
    OUT("getline=%d\n", BIO_get_line(m, buf, sizeof(buf)));
    OUT("getline.out=%s\n", buf);
    memset(buf, 0, sizeof(buf));
    OUT("getline.2=%d\n", BIO_get_line(m, buf, sizeof(buf)));
    OUT("getline.2.out=%s\n", buf);
    BIO_free(m);

    OUT("\n# end\n");
    return 0;
}
