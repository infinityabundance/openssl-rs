/*
 * rt_ui_probe.c -- RT-UI: the Phase-13.4 UI framework, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer or a fixed string -- never an address, never a clock, never the
 * error queue. Where a pointer's *identity* matters it is compared against a fixed object this
 * probe owns and printed as 0/1, so no address reaches the transcript.
 *
 * ## What this probe drives
 *
 * All 62 `ui.h` exports, whose bodies the earlier strata landed as substrate:
 *
 *   * the object lifecycle -- `UI_new`, `UI_new_method`, `UI_free`, `UI_get_method`/`UI_set_method`,
 *     `UI_get_default_method`/`UI_set_default_method`, and the two ex-data accessors;
 *   * the string additions -- `UI_add_input_string`, `UI_add_verify_string`,
 *     `UI_add_input_boolean`, `UI_add_info_string`, `UI_add_error_string`, and every `UI_dup_*`
 *     twin, plus their refusal arms (a NULL prompt, a NULL result buffer, a NULL `ok_chars` or
 *     `cancel_chars`, and the overlapping-`ok`/`cancel` arm, which raises but still allocates);
 *   * `UI_process` over a caller-supplied `UI_METHOD` whose callbacks are deterministic functions
 *     this probe owns, so no terminal is ever opened. The writer observes every `UI_STRING`'s type,
 *     input flags, output/action/test strings and size bounds; the reader supplies fixed answers
 *     through `UI_set_result`/`UI_set_result_ex`;
 *   * the result accessors -- `UI_get0_result`/`UI_get_result_length` at the `UI` level and
 *     `UI_get0_result_string`/`UI_get_result_string_length` at the `UI_STRING` level, with the
 *     negative and past-the-end refusal arms;
 *   * `UI_construct_prompt`, both the default "Enter ... for ...:" spelling and a method-supplied
 *     prompt constructor;
 *   * the `UI_METHOD` construction and accessor surface -- `UI_create_method`,
 *     `UI_destroy_method`, every `UI_method_set_*`/`UI_method_get_*` pair, `UI_OpenSSL`, `UI_null`,
 *     `UI_UTIL_wrap_read_pem_callback`, and the four method-specific ex-data accessors;
 *   * `UI_UTIL_read_pw_string`/`UI_UTIL_read_pw` over memory-only methods: the default method is
 *     temporarily set to a deterministic in-process method (and to the PEM wrapper) so `UI_new`
 *     inside `UI_UTIL_read_pw` never reaches the console;
 *   * the null-method refusals -- `UI_process` cancels with `-2` on a reader-less string and
 *     answers `0` on an empty queue;
 *   * `UI_ctrl`'s two commands and its unknown-command arm.
 *
 * ## Arms that are deliberately absent
 *
 * Several setters and accessors dereference their object in both the authority and the crate
 * (`UI_method_set_ex_data`, `UI_method_get_ex_data`, `UI_set_ex_data`, `UI_get_ex_data`,
 * `UI_get_method`, `UI_set_method`, `UI_get0_user_data`, `UI_process`), so a NULL object is **not**
 * driven -- it would crash on both sides and compare nothing. `UI_method_set_*` and
 * `UI_method_get_*` (other than the ex-data pair) *do* test their method for NULL, so those NULL
 * arms are driven. `UI_create_method(NULL)` is not driven either: the authority hands the name
 * straight to `OPENSSL_strdup`. The error queue is never read and `UI_CTRL_PRINT_ERRORS` is left
 * at `0` on every UI that is processed, so the `UI_R_*` raises on the refusal arms cannot leak
 * into a comparison.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/ui.h>
#include <openssl/crypto.h>

/* Fixed objects whose addresses are only ever compared, never printed. */
static char marker_a, marker_b, marker_c;

static const char *g_tag = "x";
static int g_verbose = 1;
static int g_wc = 0;
static int g_rc = 0;
static int g_open_calls = 0;
static int g_close_calls = 0;
static int g_flush_calls = 0;
static int g_destroy_calls = 0;

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_str(const char *key, const char *s)
{
    printf("%s=%s\n", key, s != NULL ? s : "NULL");
}

/* ---------------------------------------------------------------------------------------------
 * The deterministic method: its callbacks are the probe's own, so `UI_process` never touches a
 * terminal. The reader answers every prompt with a fixed phrase and every boolean with "n".
 * ------------------------------------------------------------------------------------------- */
static int my_open(UI *ui)
{
    (void)ui;
    g_open_calls++;
    return 1;
}

static int my_close(UI *ui)
{
    (void)ui;
    g_close_calls++;
    return 1;
}

static int my_flush(UI *ui)
{
    (void)ui;
    g_flush_calls++;
    return 1;
}

static int my_write(UI *ui, UI_STRING *uis)
{
    int n = g_wc++;
    char key[80];

    (void)ui;
    if (!g_verbose)
        return 1;

    /* Every accessor is type-guarded in the authority and in the crate, so calling all of them on
     * every string type is safe and deterministic. */
    snprintf(key, sizeof key, "%s.w%d.type", g_tag, n);
    out_int(key, UI_get_string_type(uis));
    snprintf(key, sizeof key, "%s.w%d.input_flags", g_tag, n);
    out_int(key, UI_get_input_flags(uis));
    snprintf(key, sizeof key, "%s.w%d.output", g_tag, n);
    out_str(key, UI_get0_output_string(uis));
    snprintf(key, sizeof key, "%s.w%d.action", g_tag, n);
    out_str(key, UI_get0_action_string(uis));
    snprintf(key, sizeof key, "%s.w%d.test", g_tag, n);
    out_str(key, UI_get0_test_string(uis));
    snprintf(key, sizeof key, "%s.w%d.minsize", g_tag, n);
    out_int(key, UI_get_result_minsize(uis));
    snprintf(key, sizeof key, "%s.w%d.maxsize", g_tag, n);
    out_int(key, UI_get_result_maxsize(uis));
    /* Before any read: the result accessors report the empty state. */
    snprintf(key, sizeof key, "%s.w%d.resultp", g_tag, n);
    out_int(key, UI_get0_result_string(uis) != NULL);
    snprintf(key, sizeof key, "%s.w%d.resultlen", g_tag, n);
    out_int(key, UI_get_result_string_length(uis));
    return 1;
}

static int my_read(UI *ui, UI_STRING *uis)
{
    int n = g_rc++;
    int t = UI_get_string_type(uis);
    char key[80];

    if (t == UIT_PROMPT || t == UIT_VERIFY) {
        int rc = UI_set_result(ui, uis, "abc");
        if (g_verbose) {
            snprintf(key, sizeof key, "%s.r%d.setret", g_tag, n);
            out_int(key, rc);
            snprintf(key, sizeof key, "%s.r%d.len", g_tag, n);
            out_int(key, UI_get_result_string_length(uis));
            snprintf(key, sizeof key, "%s.r%d.value", g_tag, n);
            out_str(key, UI_get0_result_string(uis));
        }
    } else if (t == UIT_BOOLEAN) {
        int rc = UI_set_result_ex(ui, uis, "n", 1);
        if (g_verbose) {
            snprintf(key, sizeof key, "%s.r%d.setret", g_tag, n);
            out_int(key, rc);
            snprintf(key, sizeof key, "%s.r%d.len", g_tag, n);
            out_int(key, UI_get_result_string_length(uis));
            snprintf(key, sizeof key, "%s.r%d.resultp", g_tag, n);
            out_int(key, UI_get0_result_string(uis) != NULL);
        }
    }
    return 1;
}

static void *my_dup_data(UI *ui, void *data)
{
    (void)ui;
    (void)data;
    return &marker_b;
}

static void my_destroy_data(UI *ui, void *data)
{
    (void)ui;
    (void)data;
    g_destroy_calls++;
}

static char g_custom_prompt[] = "custom prompt";
static char *my_ctor(UI *ui, const char *desc, const char *name)
{
    (void)ui;
    (void)desc;
    (void)name;
    return g_custom_prompt;
}

/* A `pem_password_cb` that copies a fixed phrase, so a read through the wrapper is observable. */
static int fixed_pw_cb(char *buf, int size, int rwflag, void *u)
{
    const char *pw = "swordfish";

    (void)rwflag;
    (void)u;
    if (size < (int)strlen(pw) + 1)
        return -1;
    memcpy(buf, pw, strlen(pw));
    return (int)strlen(pw);
}

static void reset_counters(const char *tag, int verbose)
{
    g_tag = tag;
    g_verbose = verbose;
    g_wc = 0;
    g_rc = 0;
    g_open_calls = 0;
    g_close_calls = 0;
    g_flush_calls = 0;
}

int main(void)
{
    UI_METHOD *m, *m2, *ctor_meth, *wr, *wrnull;
    UI *ui, *uid, *uin, *uin2, *uictl, *uimeth;
    int i0, i1, i2, i3, i4, d0, d1, d2, d3, d4;
    int uidx, midx;
    char buf0[16], buf1[16], boolbuf[8];
    char dbuf0[16], dbuf1[16], dboolbuf[8];
    char pbuf[16], wbuf[16];
    const UI_METHOD *saved_default, *nul, *os, *null_meth;
    char *prompt;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* ----------------------------------------------------------------------------------------
     * A. The default method, `UI_OpenSSL`, `UI_null` and their callback tables.
     * -------------------------------------------------------------------------------------- */
    os = UI_OpenSSL();
    out_int("openssl.nonnull", os != NULL);
    out_int("openssl.opener", UI_method_get_opener(os) != NULL);
    out_int("openssl.writer", UI_method_get_writer(os) != NULL);
    out_int("openssl.flusher", UI_method_get_flusher(os) != NULL);
    out_int("openssl.reader", UI_method_get_reader(os) != NULL);
    out_int("openssl.closer", UI_method_get_closer(os) != NULL);
    out_int("openssl.prompt_ctor", UI_method_get_prompt_constructor(os) != NULL);
    out_int("openssl.data_dup", UI_method_get_data_duplicator(os) != NULL);
    out_int("openssl.data_destr", UI_method_get_data_destructor(os) != NULL);

    nul = UI_null();
    out_int("null.nonnull", nul != NULL);
    out_int("null.opener", UI_method_get_opener(nul) != NULL);
    out_int("null.writer", UI_method_get_writer(nul) != NULL);
    out_int("null.flusher", UI_method_get_flusher(nul) != NULL);
    out_int("null.reader", UI_method_get_reader(nul) != NULL);
    out_int("null.closer", UI_method_get_closer(nul) != NULL);
    out_int("null.prompt_ctor", UI_method_get_prompt_constructor(nul) != NULL);
    out_int("null.data_dup", UI_method_get_data_duplicator(nul) != NULL);
    out_int("null.data_destr", UI_method_get_data_destructor(nul) != NULL);
    null_meth = UI_null();

    saved_default = UI_get_default_method();
    out_int("default.nonnull", saved_default != NULL);
    out_int("default.is_openssl", saved_default == os);

    out_int("new.nonnull", (ui = UI_new()) != NULL);
    UI_free(ui);
    out_int("new_method.null_uses_default",
            UI_get_method(ui = UI_new_method(NULL)) == saved_default);
    UI_free(ui);

    UI_free(NULL);

    /* `UI_set_default_method`/`UI_get_default_method` round trip. */
    UI_set_default_method(null_meth);
    out_int("default.set_null", UI_get_default_method() == null_meth);
    UI_set_default_method(saved_default);
    out_int("default.restored", UI_get_default_method() == saved_default);

    /* ----------------------------------------------------------------------------------------
     * B. `UI_create_method` / `UI_destroy_method` and the `UI_method_set_*`/`get_*` surface.
     * -------------------------------------------------------------------------------------- */
    m = UI_create_method("rt-ui");
    out_int("create.nonnull", m != NULL);
    out_int("create.opener_null", UI_method_get_opener(m) == NULL);
    out_int("create.writer_null", UI_method_get_writer(m) == NULL);
    out_int("create.flusher_null", UI_method_get_flusher(m) == NULL);
    out_int("create.reader_null", UI_method_get_reader(m) == NULL);
    out_int("create.closer_null", UI_method_get_closer(m) == NULL);
    out_int("create.prompt_ctor_null", UI_method_get_prompt_constructor(m) == NULL);
    out_int("create.data_dup_null", UI_method_get_data_duplicator(m) == NULL);
    out_int("create.data_destr_null", UI_method_get_data_destructor(m) == NULL);

    out_int("set.opener", UI_method_set_opener(m, my_open) == 0);
    out_int("set.writer", UI_method_set_writer(m, my_write) == 0);
    out_int("set.flusher", UI_method_set_flusher(m, my_flush) == 0);
    out_int("set.reader", UI_method_set_reader(m, my_read) == 0);
    out_int("set.closer", UI_method_set_closer(m, my_close) == 0);
    out_int("get.opener_same",
            UI_method_get_opener(m) == (int (*)(UI *))my_open);
    out_int("get.writer_same",
            UI_method_get_writer(m) == (int (*)(UI *, UI_STRING *))my_write);
    out_int("get.flusher_same",
            UI_method_get_flusher(m) == (int (*)(UI *))my_flush);
    out_int("get.reader_same",
            UI_method_get_reader(m) == (int (*)(UI *, UI_STRING *))my_read);
    out_int("get.closer_same",
            UI_method_get_closer(m) == (int (*)(UI *))my_close);

    /* The NULL-method refusal arms of the seven setters that test for NULL. */
    out_int("set.opener_null", UI_method_set_opener(NULL, my_open) == -1);
    out_int("set.writer_null", UI_method_set_writer(NULL, my_write) == -1);
    out_int("set.flusher_null", UI_method_set_flusher(NULL, my_flush) == -1);
    out_int("set.reader_null", UI_method_set_reader(NULL, my_read) == -1);
    out_int("set.closer_null", UI_method_set_closer(NULL, my_close) == -1);
    out_int("set.datadup_null", UI_method_set_data_duplicator(NULL, my_dup_data,
                                                              my_destroy_data) == -1);
    out_int("set.promptctor_null", UI_method_set_prompt_constructor(NULL, my_ctor) == -1);

    /* The NULL-method arms of the eight getters that test for NULL. */
    out_int("get.opener_null", UI_method_get_opener(NULL) == NULL);
    out_int("get.writer_null", UI_method_get_writer(NULL) == NULL);
    out_int("get.flusher_null", UI_method_get_flusher(NULL) == NULL);
    out_int("get.reader_null", UI_method_get_reader(NULL) == NULL);
    out_int("get.closer_null", UI_method_get_closer(NULL) == NULL);
    out_int("get.promptctor_null", UI_method_get_prompt_constructor(NULL) == NULL);
    out_int("get.datadup_null", UI_method_get_data_duplicator(NULL) == NULL);
    out_int("get.datadestr_null", UI_method_get_data_destructor(NULL) == NULL);

    /* The duplicator/destructor pair and the prompt constructor, on a second method. */
    m2 = UI_create_method("rt-ui-dup");
    out_int("set2.datadup", UI_method_set_data_duplicator(m2, my_dup_data,
                                                          my_destroy_data) == 0);
    out_int("get2.datadup_same", UI_method_get_data_duplicator(m2) == my_dup_data);
    out_int("get2.datadestr_same", UI_method_get_data_destructor(m2) == my_destroy_data);
    ctor_meth = UI_create_method("rt-ui-ctor");
    out_int("set2.promptctor", UI_method_set_prompt_constructor(ctor_meth, my_ctor) == 0);
    out_int("get2.promptctor_same", UI_method_get_prompt_constructor(ctor_meth) == my_ctor);

    /* `UI_destroy_method(NULL)` is accepted. */
    UI_destroy_method(NULL);

    /* ----------------------------------------------------------------------------------------
     * C. The ex-data accessors: UI-level and method-level.
     * -------------------------------------------------------------------------------------- */
    uidx = UI_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    out_int("ex.ui_idx_ge0", uidx >= 0);
    ui = UI_new_method(null_meth);
    out_int("ex.ui_before_null", UI_get_ex_data(ui, uidx) == NULL);
    out_int("ex.ui_set", UI_set_ex_data(ui, uidx, &marker_a) == 1);
    out_int("ex.ui_get_a", UI_get_ex_data(ui, uidx) == &marker_a);
    UI_free(ui);

    midx = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_UI_METHOD, 0, NULL, NULL, NULL, NULL);
    out_int("ex.method_idx_ge0", midx >= 0);
    out_int("ex.method_before_null", UI_method_get_ex_data(m, midx) == NULL);
    out_int("ex.method_set", UI_method_set_ex_data(m, midx, &marker_b) == 1);
    out_int("ex.method_get_b", UI_method_get_ex_data(m, midx) == &marker_b);

    /* ----------------------------------------------------------------------------------------
     * D. `UI_new_method`/`UI_get_method`/`UI_set_method` object identity.
     * -------------------------------------------------------------------------------------- */
    uimeth = UI_new_method(null_meth);
    out_int("method.get_null", UI_get_method(uimeth) == null_meth);
    out_int("method.set_same", UI_set_method(uimeth, m) == m);
    out_int("method.get_m", UI_get_method(uimeth) == m);
    UI_free(uimeth);

    /* ----------------------------------------------------------------------------------------
     * E. User data: replace, retrieve, duplicate and destroy.
     * -------------------------------------------------------------------------------------- */
    ui = UI_new_method(m);
    out_int("userdata.old_null", UI_add_user_data(ui, &marker_a) == NULL);
    out_int("userdata.get_a", UI_get0_user_data(ui) == &marker_a);
    out_int("userdata.old_a", UI_add_user_data(ui, &marker_c) == &marker_a);
    out_int("userdata.get_c", UI_get0_user_data(ui) == &marker_c);
    out_int("userdata.dup_unsupported", UI_dup_user_data(ui, &marker_a) == -1);
    UI_free(ui);

    uid = UI_new_method(m2);
    out_int("userdata.dup_ret", UI_dup_user_data(uid, &marker_a) == 0);
    out_int("userdata.dup_get_b", UI_get0_user_data(uid) == &marker_b);
    /* A replace under the DUPL flag runs the destructor and answers NULL. */
    out_int("userdata.dup_replace_null", UI_add_user_data(uid, &marker_c) == NULL);
    out_int("userdata.dup_get_c", UI_get0_user_data(uid) == &marker_c);
    UI_free(uid);
    out_int("userdata.destroy_calls", g_destroy_calls);

    /* ----------------------------------------------------------------------------------------
     * F. `UI_construct_prompt`, default and method-supplied.
     * -------------------------------------------------------------------------------------- */
    ui = UI_new_method(null_meth);
    prompt = UI_construct_prompt(ui, "pass phrase", "foo.key");
    out_str("prompt.default_both", prompt);
    OPENSSL_free(prompt);
    prompt = UI_construct_prompt(ui, "pass phrase", NULL);
    out_str("prompt.default_desc", prompt);
    OPENSSL_free(prompt);
    out_int("prompt.default_null", UI_construct_prompt(ui, NULL, "x") == NULL);
    UI_free(ui);

    uimeth = UI_new_method(ctor_meth);
    prompt = UI_construct_prompt(uimeth, "x", "y");
    out_str("prompt.custom", prompt);
    UI_free(uimeth);
    prompt = UI_construct_prompt(NULL, "x", "y");
    out_int("prompt.null_ui", prompt == NULL);

    /* ----------------------------------------------------------------------------------------
     * G. `UI_process` over the probe's method: all five phases and every string type.
     * -------------------------------------------------------------------------------------- */
    reset_counters("main", 1);
    ui = UI_new_method(m);
    i0 = UI_add_input_string(ui, "p-input", 0, buf0, 0, 8);
    i1 = UI_add_verify_string(ui, "p-verify", UI_INPUT_FLAG_ECHO, buf1, 2, 8, "abc");
    i2 = UI_add_input_boolean(ui, "p-bool", "do it", "yY", "nN", 0, boolbuf);
    i3 = UI_add_info_string(ui, "info-text");
    i4 = UI_add_error_string(ui, "error-text");
    out_int("main.i0", i0);
    out_int("main.i1", i1);
    out_int("main.i2", i2);
    out_int("main.i3", i3);
    out_int("main.i4", i4);
    out_int("main.process_ret", UI_process(ui));
    out_int("main.open_calls", g_open_calls);
    out_int("main.flush_calls", g_flush_calls);
    out_int("main.close_calls", g_close_calls);
    out_str("main.res0", UI_get0_result(ui, 0));
    out_int("main.len0", UI_get_result_length(ui, 0));
    out_str("main.res1", UI_get0_result(ui, 1));
    out_int("main.len1", UI_get_result_length(ui, 1));
    out_str("main.res2", UI_get0_result(ui, 2));
    out_int("main.len2", UI_get_result_length(ui, 2));
    out_str("main.res3", UI_get0_result(ui, 3));
    out_int("main.len3", UI_get_result_length(ui, 3));
    out_str("main.res4", UI_get0_result(ui, 4));
    out_int("main.len4", UI_get_result_length(ui, 4));
    out_int("main.buf0", strcmp(buf0, "abc") == 0);
    out_int("main.buf1", strcmp(buf1, "abc") == 0);
    out_int("main.boolchar", boolbuf[0]);
    out_int("main.i_neg", UI_get0_result(ui, -1) == NULL);
    out_int("main.len_neg", UI_get_result_length(ui, -1));
    out_int("main.i_past", UI_get0_result(ui, 5) == NULL);
    out_int("main.len_past", UI_get_result_length(ui, 5));
    out_int("main.redoable", UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, NULL, NULL));
    UI_free(ui);

    /* ----------------------------------------------------------------------------------------
     * H. The `UI_dup_*` additions: the copied prompt/action strings are observable in the writer.
     * -------------------------------------------------------------------------------------- */
    reset_counters("dup", 1);
    uid = UI_new_method(m);
    d0 = UI_dup_input_string(uid, "d-in", 0, dbuf0, 0, 8);
    d1 = UI_dup_verify_string(uid, "d-ver", 0, dbuf1, 2, 8, "dtest");
    d2 = UI_dup_input_boolean(uid, "d-bool", "d-act", "y", "n", 0, dboolbuf);
    d3 = UI_dup_info_string(uid, "d-info");
    d4 = UI_dup_error_string(uid, "d-err");
    out_int("dup.d0", d0);
    out_int("dup.d1", d1);
    out_int("dup.d2", d2);
    out_int("dup.d3", d3);
    out_int("dup.d4", d4);
    out_int("dup.process_ret", UI_process(uid));
    out_str("dup.res0", UI_get0_result(uid, 0));
    out_int("dup.len1", UI_get_result_length(uid, 1));
    out_int("dup.boolchar", dboolbuf[0]);
    UI_free(uid);

    /* ----------------------------------------------------------------------------------------
     * I. The refusal arms of the add/dup surface.
     * -------------------------------------------------------------------------------------- */
    ui = UI_new_method(m);
    out_int("refuse.add_input_null_prompt",
            UI_add_input_string(ui, NULL, 0, buf0, 0, 8) == -1);
    out_int("refuse.add_input_null_buf",
            UI_add_input_string(ui, "p", 0, NULL, 0, 8) == -1);
    out_int("refuse.add_verify_null_prompt",
            UI_add_verify_string(ui, NULL, 0, buf0, 0, 8, "t") == -1);
    out_int("refuse.add_verify_null_buf",
            UI_add_verify_string(ui, "p", 0, NULL, 0, 8, "t") == -1);
    out_int("refuse.add_info_null", UI_add_info_string(ui, NULL) == -1);
    out_int("refuse.add_error_null", UI_add_error_string(ui, NULL) == -1);
    out_int("refuse.dup_input_null_prompt",
            UI_dup_input_string(ui, NULL, 0, buf0, 0, 8) == -1);
    out_int("refuse.dup_verify_null_prompt",
            UI_dup_verify_string(ui, NULL, 0, buf0, 0, 8, "t") == -1);
    out_int("refuse.dup_info_null", UI_dup_info_string(ui, NULL) == -1);
    out_int("refuse.dup_error_null", UI_dup_error_string(ui, NULL) == -1);
    out_int("refuse.bool_null_ok",
            UI_add_input_boolean(ui, "p", "a", NULL, "n", 0, boolbuf) == -1);
    out_int("refuse.bool_null_cancel",
            UI_add_input_boolean(ui, "p", "a", "y", NULL, 0, boolbuf) == -1);
    out_int("refuse.bool_null_buf",
            UI_add_input_boolean(ui, "p", "a", "y", "n", 0, NULL) == -1);
    out_int("refuse.dup_bool_null_ok",
            UI_dup_input_boolean(ui, "p", "a", NULL, "n", 0, boolbuf) == -1);
    /* The overlapping ok/cancel arm raises but still allocates. */
    out_int("refuse.bool_overlap_ge0",
            UI_add_input_boolean(ui, "p", "a", "ab", "bc", 0, boolbuf) >= 1);
    UI_free(ui);

    /* ----------------------------------------------------------------------------------------
     * J. `UI_ctrl`: the two commands and the unknown-command arm.
     * -------------------------------------------------------------------------------------- */
    uictl = UI_new_method(m);
    out_int("ctrl.print_prev0", UI_ctrl(uictl, UI_CTRL_PRINT_ERRORS, 1, NULL, NULL) == 0);
    out_int("ctrl.print_prev1", UI_ctrl(uictl, UI_CTRL_PRINT_ERRORS, 1, NULL, NULL) == 1);
    out_int("ctrl.print_prev1b", UI_ctrl(uictl, UI_CTRL_PRINT_ERRORS, 0, NULL, NULL) == 1);
    out_int("ctrl.print_prev0b", UI_ctrl(uictl, UI_CTRL_PRINT_ERRORS, 0, NULL, NULL) == 0);
    out_int("ctrl.redoable0", UI_ctrl(uictl, UI_CTRL_IS_REDOABLE, 0, NULL, NULL) == 0);
    out_int("ctrl.unknown", UI_ctrl(uictl, 12345, 0, NULL, NULL) == -1);
    out_int("ctrl.null", UI_ctrl(NULL, UI_CTRL_PRINT_ERRORS, 1, NULL, NULL) == -1);
    UI_free(uictl);

    /* ----------------------------------------------------------------------------------------
     * K. The null method: a reader-less string cancels, an empty queue succeeds.
     * -------------------------------------------------------------------------------------- */
    uin = UI_new_method(null_meth);
    out_int("nullui.add", UI_add_input_string(uin, "p", 0, buf0, 0, 8) >= 1);
    out_int("nullui.process_cancel", UI_process(uin) == -2);
    out_int("nullui.redoable", UI_ctrl(uin, UI_CTRL_IS_REDOABLE, 0, NULL, NULL) == 0);
    UI_free(uin);

    uin2 = UI_new_method(UI_null());
    out_int("nullui.empty_process", UI_process(uin2) == 0);
    UI_free(uin2);

    /* ----------------------------------------------------------------------------------------
     * L. `UI_UTIL_read_pw`/`_read_pw_string` and the PEM wrapper, over in-process methods only.
     * -------------------------------------------------------------------------------------- */
    memset(pbuf, 0, sizeof pbuf);
    memset(wbuf, 0, sizeof wbuf);
    out_int("readpw.size_zero", UI_UTIL_read_pw(pbuf, wbuf, 0, "pw:", 0) == -1);

    /* Install the probe's own method as the default so `UI_new` inside `UI_UTIL_read_pw` is
     * deterministic; restore afterwards. */
    reset_counters("readpw", 0);
    UI_set_default_method(m);
    memset(pbuf, 0, sizeof pbuf);
    memset(wbuf, 0, sizeof wbuf);
    out_int("readpw.ret", UI_UTIL_read_pw(pbuf, wbuf, 16, "pw:", 0));
    out_str("readpw.buf", pbuf);
    memset(pbuf, 0, sizeof pbuf);
    out_int("readpw.verify_ret", UI_UTIL_read_pw(pbuf, wbuf, 16, "pw:", 1));
    out_str("readpw.verify_buf", pbuf);
    memset(pbuf, 0, sizeof pbuf);
    out_int("readpw.string_ret", UI_UTIL_read_pw_string(pbuf, 16, "pw:", 0));
    out_str("readpw.string_buf", pbuf);

    /* `UI_UTIL_wrap_read_pem_callback` and its reader, driven through `UI_UTIL_read_pw`. */
    wr = UI_UTIL_wrap_read_pem_callback(fixed_pw_cb, 0);
    out_int("wrap.nonnull", wr != NULL);
    out_int("wrap.opener", UI_method_get_opener(wr) != NULL);
    out_int("wrap.writer", UI_method_get_writer(wr) != NULL);
    out_int("wrap.flusher_null", UI_method_get_flusher(wr) == NULL);
    out_int("wrap.reader", UI_method_get_reader(wr) != NULL);
    out_int("wrap.closer", UI_method_get_closer(wr) != NULL);
    UI_set_default_method(wr);
    memset(pbuf, 0, sizeof pbuf);
    out_int("wrap.readpw_ret", UI_UTIL_read_pw(pbuf, wbuf, 16, "pw:", 0));
    out_str("wrap.readpw_buf", pbuf);
    UI_set_default_method(saved_default);
    UI_destroy_method(wr);

    wrnull = UI_UTIL_wrap_read_pem_callback(NULL, 1);
    out_int("wrapnull.nonnull", wrnull != NULL);
    out_int("wrapnull.reader", UI_method_get_reader(wrnull) != NULL);
    UI_destroy_method(wrnull);

    UI_set_default_method(saved_default);
    out_int("default.final_restored", UI_get_default_method() == saved_default);

    /* ----------------------------------------------------------------------------------------
     * M. Release the probe-owned methods.
     * -------------------------------------------------------------------------------------- */
    UI_destroy_method(m);
    UI_destroy_method(m2);
    UI_destroy_method(ctor_meth);

    out_int("probe.done", 1);
    return 0;
}
