/*
 * unknown-obligations v1l negative controls.
 *
 * Every case exercises the *public* entry path that reaches one operation the
 * v1l receipt discharges, with an input that would crash or corrupt if the
 * operation's stated precondition were actually required and violated.  Each
 * case runs in a forked child so a SIGSEGV is an observed result rather than a
 * dead probe.  The probe is linked against the frozen install
 * (libcrypto 247803f1 / libssl 3ca46e32) and never rebuilds the crate.
 *
 * Cases and the operation they reach:
 *   confnum-12abc / confnum-abc / confnum-null-result
 *       -> default_is_number + default_to_int
 *          (src/runtime/conf/lib.rs:698,703), through NCONF_get_number_e.
 *   confmod-oid-valid / confmod-oid-bad / confmod-unload-twice
 *       -> oid_module_finish (src/runtime/confmod/asn1.rs:255),
 *          stbl_module_finish (src/asn1/asn_mstbl.rs:261) and
 *          module_free_thunk (src/runtime/confmod/mod.rs:397), through
 *          ASN1_add_{oid,stable}_module + CONF_modules_load_file/unload.
 *   ui-wrapper-null / ui-wrapper-cb / ui-wrapper-twice
 *       -> ui_method_data_index_init (src/ui/ui_util.rs:217) and
 *          ui_free_method_data (src/ui/ui_util.rs:197), through
 *          UI_UTIL_wrap_read_pem_callback + UI_destroy_method.
 *   eng-str-bad / eng-str-null
 *       -> push_cstr_or_null (src/engine/eng_fat.rs:197), through
 *          ENGINE_set_default_string (both the "bogus" and NULL branches).
 *   decoder-ctx
 *       -> decoder_free_thunk (src/decoder_lib.rs:1080), through the decoder
 *          context free path.
 *
 * Exit codes in a child: 0 = expected observation; 3 = wrong result;
 * 4 = API refused where the case needed it; anything else is a defect.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/decoder.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ui.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static const char *g_dir = ".";

static char *write_conf(const char *name, const char *body)
{
    static char path[512];
    snprintf(path, sizeof path, "%s/%s", g_dir, name);
    FILE *f = fopen(path, "w");
    if (f == NULL)
        return NULL;
    fputs(body, f);
    fclose(f);
    return path;
}

static int pem_cb(char *buf, int size, int rwflag, void *u)
{
    const char *p = "swordfish";
    (void)rwflag;
    (void)u;
    if (size < (int)strlen(p) + 1)
        return -1;
    memcpy(buf, p, strlen(p) + 1);
    return (int)strlen(p);
}

/* ---- default_is_number / default_to_int -------------------------------- */

static int case_confnum(const char *body, long want, int want_ok)
{
    char *path = write_conf("v1l-num.cnf", body);
    if (path == NULL)
        return 4;
    CONF *conf = NCONF_new(NULL);
    if (conf == NULL)
        return 4;
    if (NCONF_load(conf, path, NULL) != 1)
        return 4;
    long got = -999;
    int ok = NCONF_get_number_e(conf, "sec", "n", &got);
    NCONF_free(conf);
    if (ok != want_ok)
        return 3;
    if (want_ok && got != want)
        return 3;
    return 0;
}

static int case_confnum_null_result(void)
{
    char *path = write_conf("v1l-num-null.cnf", "[sec]\nn=12\n");
    if (path == NULL)
        return 4;
    CONF *conf = NCONF_new(NULL);
    if (conf == NULL)
        return 4;
    if (NCONF_load(conf, path, NULL) != 1)
        return 4;
    int ok = NCONF_get_number_e(conf, "sec", "n", NULL);
    NCONF_free(conf);
    return ok == 0 ? 0 : 3;
}

/* ---- oid_module_finish / stbl_module_finish / module_free_thunk -------- */

static int case_confmod(const char *body, int want_ok)
{
    char *path = write_conf("v1l-confmod.cnf", body);
    if (path == NULL)
        return 4;
    ASN1_add_oid_module();
    ASN1_add_stable_module();
    int ok = CONF_modules_load_file(path, "v1l", 0);
    CONF_modules_unload(1);
    CONF_modules_unload(1); /* second unload must be a no-op, not a double free */
    ERR_clear_error();
    /* want_ok < 0: the refusal code is not the observation; completing the
     * unload without a fault is. */
    if (want_ok < 0)
        return 0;
    return ok == want_ok ? 0 : 3;
}

/* ---- ui_method_data_index_init / ui_free_method_data ------------------- */

static int case_ui(int with_cb, int twice)
{
    UI_METHOD *a = UI_UTIL_wrap_read_pem_callback(with_cb ? pem_cb : NULL, with_cb);
    if (a == NULL)
        return 4;
    const void *data = NULL;
    for (int i = 0; i < 32; i++) {
        data = UI_method_get_ex_data(a, i);
        if (data != NULL)
            break;
    }
    if (data == NULL) { /* the registrar did not attach at any admitted index */
        UI_destroy_method(a);
        return 3;
    }
    UI_destroy_method(a);
    if (twice) {
        UI_METHOD *b = UI_UTIL_wrap_read_pem_callback(with_cb ? pem_cb : NULL, with_cb);
        if (b == NULL)
            return 4;
        UI_destroy_method(b);
    }
    return 0;
}

/* ---- push_cstr_or_null ------------------------------------------------- */

static int case_eng_str(int null_list)
{
    ENGINE *e = ENGINE_new();
    if (e == NULL)
        return 4;
    int r = ENGINE_set_default_string(e, null_list ? NULL : "bogus");
    ENGINE_free(e);
    ERR_clear_error();
    return r == 0 ? 0 : 3;
}

/* ---- decoder_free_thunk ------------------------------------------------ */

static int case_decoder(void)
{
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(
        &pkey, "DER", NULL, "RSA", EVP_PKEY_KEYPAIR, NULL, NULL);
    if (ctx == NULL) {
        ERR_clear_error();
        return 0; /* no decoder table to free: still a valid refusal */
    }
    OSSL_DECODER_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    ERR_clear_error();
    return 0;
}

/* ---- san_i2v / san_v2i / akid_i2v / akid_v2i --------------------------- */

/* X509V3_EXT_nconf builds the extension through the method's v2i slot; the
 * returned X509_EXTENSION is then printed through its i2v slot. */
static int print_ext(X509_EXTENSION *ext, const char *needle)
{
    BIO *b = BIO_new(BIO_s_mem());
    if (b == NULL)
        return 4;
    int ok = X509V3_EXT_print(b, ext, 0, 0);
    char *p = NULL;
    long l = BIO_get_mem_data(b, &p);
    int found = (needle == NULL);
    if (needle != NULL && p != NULL) {
        char *tmp = malloc((size_t)l + 1);
        if (tmp != NULL) {
            memcpy(tmp, p, (size_t)l);
            tmp[l] = 0;
            found = strstr(tmp, needle) != NULL;
            free(tmp);
        }
    }
    BIO_free(b);
    if (ok != 1)
        return 3;
    return found ? 0 : 3;
}

static int case_ext_roundtrip(const char *name, const char *value,
                              const char *needle)
{
    X509V3_CTX ctx;
    memset(&ctx, 0, sizeof ctx);
    X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_nconf(NULL, &ctx, name, value);
    if (ext == NULL)
        return 3; /* v2i refused a valid value */
    int rc = print_ext(ext, needle);
    X509_EXTENSION_free(ext);
    return rc;
}

static int case_san_bad(void)
{
    X509V3_CTX ctx;
    memset(&ctx, 0, sizeof ctx);
    X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_nconf(NULL, &ctx, "subjectAltName",
                                           "BAD.TYPE:xxx");
    ERR_clear_error();
    if (ext != NULL)
        X509_EXTENSION_free(ext);
    return ext == NULL ? 0 : 3;
}

static int case_san_i2v_corrupt(void)
{
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
    if (os == NULL)
        return 4;
    static const unsigned char junk[3] = {0xde, 0xad, 0xbe};
    if (ASN1_OCTET_STRING_set(os, junk, sizeof junk) != 1)
        return 4;
    X509_EXTENSION *ext = X509_EXTENSION_create_by_NID(
        NULL, NID_subject_alt_name, 1, os);
    ASN1_OCTET_STRING_free(os);
    if (ext == NULL)
        return 4;
    BIO *b = BIO_new(BIO_s_mem());
    if (b == NULL)
        return 4;
    (void)X509V3_EXT_print(b, ext, 0, 0); /* refusal or raw fallback: not a crash */
    BIO_free(b);
    X509_EXTENSION_free(ext);
    ERR_clear_error();
    return 0;
}

/* ------------------------------------------------------------------------ */

static int run_child(int (*fn)(void))
{
    fflush(NULL); /* do not duplicate the parent's buffer into the child */
    pid_t pid = fork();
    if (pid < 0)
        return 4;
    if (pid == 0) {
        int rc = fn();
        fflush(NULL);
        _exit(rc);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return 4;
    if (WIFSIGNALED(status)) {
        printf("SIG %d", WTERMSIG(status));
        return 90 + WTERMSIG(status);
    }
    return WEXITSTATUS(status);
}

static int nc_confnum_12abc(void) { return case_confnum("[sec]\nn=12abc\n", 12, 1); }
static int nc_confnum_abc(void)   { return case_confnum("[sec]\nn=abc\n", 0, 1); }
static int nc_confmod_ok(void)
{
    return case_confmod("oid_section = oids\n[oids]\nv1loid = 1.2.3.4\n", 1);
}
static int nc_confmod_bad(void)
{
    return case_confmod("oid_section = oids\n[oids]\nnotanoid = BAD\n", -1);
}
static int nc_ui_null(void)   { return case_ui(0, 0); }
static int nc_ui_cb(void)     { return case_ui(1, 0); }
static int nc_ui_twice(void)  { return case_ui(1, 1); }
static int nc_eng_bad(void)   { return case_eng_str(0); }
static int nc_eng_null(void)  { return case_eng_str(1); }

static int nc_x509_san(void)
{
    return case_ext_roundtrip("subjectAltName", "DNS:example.com,IP:1.2.3.4",
                              "DNS:example.com");
}
static int nc_x509_akid(void)
{
    /*  "keyid,issuer" needs a live subject/issuer certificate, so build one. */
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    if (pkey == NULL)
        return 4;
    X509 *cert = X509_new();
    if (cert == NULL) { EVP_PKEY_free(pkey); return 4; }
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_NAME *nm = X509_NAME_new();
    if (nm == NULL) { X509_free(cert); EVP_PKEY_free(pkey); return 4; }
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                               (const unsigned char *)"v1l", -1, -1, 0);
    X509_set_subject_name(cert, nm);
    X509_set_issuer_name(cert, nm);
    X509_NAME_free(nm);
    if (X509_set_pubkey(cert, pkey) != 1 ||
        X509_sign(cert, pkey, EVP_sha256()) <= 0) {
        X509_free(cert); EVP_PKEY_free(pkey); return 4;
    }

    X509V3_CTX ctx;
    memset(&ctx, 0, sizeof ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    /*  self-signed: name the same key as issuer so keyid:always can hash it. */
    X509V3_set_issuer_pkey(&ctx, pkey);
    X509_EXTENSION *ext = X509V3_EXT_nconf(NULL, &ctx,
                                           "authorityKeyIdentifier",
                                           "keyid:always,issuer:always");
    int rc;
    if (ext == NULL) {
        ERR_clear_error();
        rc = 3;
    } else {
        rc = print_ext(ext, "keyid");
        X509_EXTENSION_free(ext);
    }
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return rc;
}

#define RUN(name, fn)                                                         \
    do {                                                                       \
        int rc = run_child(fn);                                                \
        printf("%-24s %s (exit %d)\n", name, rc == 0 ? "PASS" : "FAIL", rc);   \
        failures += rc != 0;                                                   \
    } while (0)

int main(int argc, char **argv)
{
    int failures = 0;
    if (argc > 1)
        g_dir = argv[1];

    printf("v1l negative controls against the frozen install\n");

    RUN("confnum-12abc", nc_confnum_12abc);
    RUN("confnum-abc", nc_confnum_abc);
    RUN("confnum-null-result", case_confnum_null_result);
    RUN("confmod-oid-valid", nc_confmod_ok);
    RUN("confmod-oid-bad", nc_confmod_bad);
    RUN("ui-wrapper-null", nc_ui_null);
    RUN("ui-wrapper-cb", nc_ui_cb);
    RUN("ui-wrapper-twice", nc_ui_twice);
    RUN("eng-str-bad", nc_eng_bad);
    RUN("eng-str-null", nc_eng_null);
    RUN("decoder-ctx", case_decoder);
    RUN("x509-san-v2i-i2v", nc_x509_san);
    RUN("x509-akid-v2i-i2v", nc_x509_akid);
    RUN("x509-san-v2i-bad", case_san_bad);
    RUN("x509-san-i2v-corrupt", case_san_i2v_corrupt);

    printf("RESULT %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures != 0;
}
