/*
 * etp5_harness.c - ETP-T5 differential harness.
 *
 * Loads exactly one libcrypto.so.3 with dlopen(RTLD_NOW | RTLD_LOCAL) and
 * serves a line-oriented case file through the OpenSSL-compatible C ABI.  The
 * harness itself is not linked against libcrypto; every entry point is
 * resolved with dlsym, so the same binary can drive the candidate and the
 * pinned authority.
 *
 * Case line:   <id> <op> <arg> ...
 * Result line: <id> ok <field> ...
 *              <id> err <reason>
 *
 * Operations:
 *   modadd  <m> <a> <b>            BN_mod_add(a,b,m)          32-byte hex
 *   modsub  <m> <a> <b>            BN_mod_sub(a,b,m)          32-byte hex
 *   modmul  <m> <a> <b>            BN_mod_mul(a,b,m)          32-byte hex
 *   modinv  <m> <a>                BN_mod_inverse(a,m)        32-byte hex
 *   modexp  <m> <a> <e>            BN_mod_exp(a,e,m)          32-byte hex
 *   scalarmul <k>                  k*G on P-256               SEC1 octets
 *   ecdsa_sign <digest> <d> <kinv> <r> <qx> <qy>
 *                                  ECDSA_do_sign_ex           r s verify
 *   ecdsa_verify <digest> <r> <s> <qx> <qy>
 *                                  ECDSA_do_verify            1 or 0
 *   rsa_private <c>                RSA_private_encrypt(NO_PADDING)
 *                                                             256-byte hex
 *   rsa_check                      RSA_check_key              1 or 0
 *   sha256 <hex | ->               SHA256(data,len,out)       64 hex chars
 *
 * The RSA key is read from the optional --rsa-key file, one "name=hex" line
 * per component: n, e, d, p, q, dmp1, dmq1, iqmp.
 */

#define _GNU_SOURCE
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *lib_handle;

static BIGNUM *(*p_BN_new)(void);
static void (*p_BN_free)(BIGNUM *);
static BN_CTX *(*p_BN_CTX_new)(void);
static void (*p_BN_CTX_free)(BN_CTX *);
static int (*p_BN_hex2bn)(BIGNUM **, const char *);
static int (*p_BN_bn2binpad)(const BIGNUM *, unsigned char *, int);
static int (*p_BN_mod_add)(BIGNUM *, const BIGNUM *, const BIGNUM *,
                           const BIGNUM *, BN_CTX *);
static int (*p_BN_mod_sub)(BIGNUM *, const BIGNUM *, const BIGNUM *,
                           const BIGNUM *, BN_CTX *);
static int (*p_BN_mod_mul)(BIGNUM *, const BIGNUM *, const BIGNUM *,
                           const BIGNUM *, BN_CTX *);
static BIGNUM *(*p_BN_mod_inverse)(BIGNUM *, const BIGNUM *, const BIGNUM *,
                                   BN_CTX *);
static int (*p_BN_mod_exp)(BIGNUM *, const BIGNUM *, const BIGNUM *,
                           const BIGNUM *, BN_CTX *);

static EC_KEY *(*p_EC_KEY_new_by_curve_name)(int);
static void (*p_EC_KEY_free)(EC_KEY *);
static const EC_GROUP *(*p_EC_KEY_get0_group)(const EC_KEY *);
static int (*p_EC_KEY_set_private_key)(EC_KEY *, const BIGNUM *);
static int (*p_EC_KEY_set_public_key)(EC_KEY *, const EC_POINT *);
static EC_POINT *(*p_EC_POINT_new)(const EC_GROUP *);
static void (*p_EC_POINT_free)(EC_POINT *);
static int (*p_EC_POINT_mul)(const EC_GROUP *, EC_POINT *, const BIGNUM *,
                             const EC_POINT *, const BIGNUM *, BN_CTX *);
static size_t (*p_EC_POINT_point2oct)(const EC_GROUP *, const EC_POINT *,
                                      point_conversion_form_t, unsigned char *,
                                      size_t, BN_CTX *);
static int (*p_EC_POINT_oct2point)(const EC_GROUP *, EC_POINT *,
                                   const unsigned char *, size_t, BN_CTX *);

static ECDSA_SIG *(*p_ECDSA_do_sign_ex)(const unsigned char *, int,
                                        const BIGNUM *, const BIGNUM *,
                                        EC_KEY *);
static int (*p_ECDSA_do_verify)(const unsigned char *, int, const ECDSA_SIG *,
                                EC_KEY *);
static void (*p_ECDSA_SIG_get0)(const ECDSA_SIG *, const BIGNUM **,
                                const BIGNUM **);
static ECDSA_SIG *(*p_ECDSA_SIG_new)(void);
static int (*p_ECDSA_SIG_set0)(ECDSA_SIG *, BIGNUM *, BIGNUM *);
static void (*p_ECDSA_SIG_free)(ECDSA_SIG *);

static RSA *(*p_RSA_new)(void);
static void (*p_RSA_free)(RSA *);
static int (*p_RSA_set0_key)(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
static int (*p_RSA_set0_factors)(RSA *, BIGNUM *, BIGNUM *);
static int (*p_RSA_set0_crt_params)(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
static int (*p_RSA_private_encrypt)(int, const unsigned char *, unsigned char *,
                                    RSA *, int);
static int (*p_RSA_check_key)(const RSA *);

static unsigned char *(*p_SHA256)(const unsigned char *, size_t,
                                  unsigned char *);

static RSA *rsa_key;

static void die(const char *message)
{
    fprintf(stderr, "etp5_harness: %s\n", message);
    exit(2);
}

static void *sym(const char *name)
{
    void *address = dlsym(lib_handle, name);
    if (address == NULL)
        die(name);
    return address;
}

static void load_symbols(void)
{
    *(void **)(&p_BN_new) = sym("BN_new");
    *(void **)(&p_BN_free) = sym("BN_free");
    *(void **)(&p_BN_CTX_new) = sym("BN_CTX_new");
    *(void **)(&p_BN_CTX_free) = sym("BN_CTX_free");
    *(void **)(&p_BN_hex2bn) = sym("BN_hex2bn");
    *(void **)(&p_BN_bn2binpad) = sym("BN_bn2binpad");
    *(void **)(&p_BN_mod_add) = sym("BN_mod_add");
    *(void **)(&p_BN_mod_sub) = sym("BN_mod_sub");
    *(void **)(&p_BN_mod_mul) = sym("BN_mod_mul");
    *(void **)(&p_BN_mod_inverse) = sym("BN_mod_inverse");
    *(void **)(&p_BN_mod_exp) = sym("BN_mod_exp");

    *(void **)(&p_EC_KEY_new_by_curve_name) = sym("EC_KEY_new_by_curve_name");
    *(void **)(&p_EC_KEY_free) = sym("EC_KEY_free");
    *(void **)(&p_EC_KEY_get0_group) = sym("EC_KEY_get0_group");
    *(void **)(&p_EC_KEY_set_private_key) = sym("EC_KEY_set_private_key");
    *(void **)(&p_EC_KEY_set_public_key) = sym("EC_KEY_set_public_key");
    *(void **)(&p_EC_POINT_new) = sym("EC_POINT_new");
    *(void **)(&p_EC_POINT_free) = sym("EC_POINT_free");
    *(void **)(&p_EC_POINT_mul) = sym("EC_POINT_mul");
    *(void **)(&p_EC_POINT_point2oct) = sym("EC_POINT_point2oct");
    *(void **)(&p_EC_POINT_oct2point) = sym("EC_POINT_oct2point");

    *(void **)(&p_ECDSA_do_sign_ex) = sym("ECDSA_do_sign_ex");
    *(void **)(&p_ECDSA_do_verify) = sym("ECDSA_do_verify");
    *(void **)(&p_ECDSA_SIG_get0) = sym("ECDSA_SIG_get0");
    *(void **)(&p_ECDSA_SIG_new) = sym("ECDSA_SIG_new");
    *(void **)(&p_ECDSA_SIG_set0) = sym("ECDSA_SIG_set0");
    *(void **)(&p_ECDSA_SIG_free) = sym("ECDSA_SIG_free");

    *(void **)(&p_RSA_new) = sym("RSA_new");
    *(void **)(&p_RSA_free) = sym("RSA_free");
    *(void **)(&p_RSA_set0_key) = sym("RSA_set0_key");
    *(void **)(&p_RSA_set0_factors) = sym("RSA_set0_factors");
    *(void **)(&p_RSA_set0_crt_params) = sym("RSA_set0_crt_params");
    *(void **)(&p_RSA_private_encrypt) = sym("RSA_private_encrypt");
    *(void **)(&p_RSA_check_key) = sym("RSA_check_key");

    *(void **)(&p_SHA256) = sym("SHA256");
}

static BIGNUM *bn_from_hex(const char *hex)
{
    BIGNUM *value = NULL;
    if (p_BN_hex2bn(&value, hex) == 0)
        return NULL;
    return value;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static size_t hex_to_bytes(const char *hex, unsigned char *out, size_t cap)
{
    size_t length = strlen(hex);
    size_t index;
    if (length == 1 && hex[0] == '-')
        return 0;
    if (length % 2 != 0)
        die("odd-length hex argument");
    if (length / 2 > cap)
        die("hex argument too long");
    for (index = 0; index < length; index += 2) {
        int high = hex_nibble(hex[index]);
        int low = hex_nibble(hex[index + 1]);
        if (high < 0 || low < 0)
            die("non-hex argument");
        out[index / 2] = (unsigned char)((high << 4) | low);
    }
    return length / 2;
}

static void print_hex(const unsigned char *data, size_t length)
{
    size_t index;
    for (index = 0; index < length; index++)
        printf("%02x", data[index]);
}

static int print_bn32(const BIGNUM *value)
{
    unsigned char buffer[32];
    memset(buffer, 0, sizeof(buffer));
    if (p_BN_bn2binpad(value, buffer, 32) < 0) {
        printf(" overflow");
        return 0;
    }
    printf(" ");
    print_hex(buffer, sizeof(buffer));
    return 1;
}

static RSA *load_rsa_key(const char *path)
{
    FILE *handle = fopen(path, "r");
    char line[8192];
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
    BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    RSA *rsa;
    if (handle == NULL)
        die("cannot open RSA key file");
    while (fgets(line, sizeof(line), handle) != NULL) {
        char *eq = strchr(line, '=');
        char *value;
        if (eq == NULL)
            continue;
        *eq = '\0';
        value = eq + 1;
        value[strcspn(value, "\r\n")] = '\0';
        if (strcmp(line, "n") == 0)
            n = bn_from_hex(value);
        else if (strcmp(line, "e") == 0)
            e = bn_from_hex(value);
        else if (strcmp(line, "d") == 0)
            d = bn_from_hex(value);
        else if (strcmp(line, "p") == 0)
            p = bn_from_hex(value);
        else if (strcmp(line, "q") == 0)
            q = bn_from_hex(value);
        else if (strcmp(line, "dmp1") == 0)
            dmp1 = bn_from_hex(value);
        else if (strcmp(line, "dmq1") == 0)
            dmq1 = bn_from_hex(value);
        else if (strcmp(line, "iqmp") == 0)
            iqmp = bn_from_hex(value);
    }
    fclose(handle);
    if (n == NULL || e == NULL || d == NULL || p == NULL || q == NULL ||
        dmp1 == NULL || dmq1 == NULL || iqmp == NULL)
        die("incomplete RSA key file");
    rsa = p_RSA_new();
    if (rsa == NULL)
        die("RSA_new failed");
    if (p_RSA_set0_key(rsa, n, e, d) != 1)
        die("RSA_set0_key failed");
    if (p_RSA_set0_factors(rsa, p, q) != 1)
        die("RSA_set0_factors failed");
    if (p_RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) != 1)
        die("RSA_set0_crt_params failed");
    return rsa;
}

static EC_KEY *new_p256_key(void)
{
    EC_KEY *key = p_EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL)
        die("EC_KEY_new_by_curve_name failed");
    return key;
}

static int set_public_key(EC_KEY *key, BN_CTX *ctx, const char *qx,
                          const char *qy)
{
    const EC_GROUP *group = p_EC_KEY_get0_group(key);
    EC_POINT *point = p_EC_POINT_new(group);
    unsigned char octets[65];
    BIGNUM *x = bn_from_hex(qx);
    BIGNUM *y = bn_from_hex(qy);
    int ok;
    if (point == NULL || x == NULL || y == NULL)
        die("public point allocation failed");
    octets[0] = 4;
    if (p_BN_bn2binpad(x, octets + 1, 32) != 32 ||
        p_BN_bn2binpad(y, octets + 33, 32) != 32)
        die("public coordinate is wider than 32 bytes");
    ok = p_EC_POINT_oct2point(group, point, octets, sizeof(octets), ctx);
    if (ok == 1)
        ok = p_EC_KEY_set_public_key(key, point);
    p_EC_POINT_free(point);
    p_BN_free(x);
    p_BN_free(y);
    return ok;
}

static void op_mod(const char *op, char **arg, int count)
{
    BN_CTX *ctx;
    BIGNUM *m, *a, *b, *r;
    int ok = 0;
    if (count != 3)
        die("mod operation arity");
    ctx = p_BN_CTX_new();
    m = bn_from_hex(arg[0]);
    a = bn_from_hex(arg[1]);
    b = bn_from_hex(arg[2]);
    r = p_BN_new();
    if (ctx == NULL || m == NULL || a == NULL || b == NULL || r == NULL)
        die("mod allocation failed");
    if (strcmp(op, "modadd") == 0)
        ok = p_BN_mod_add(r, a, b, m, ctx);
    else if (strcmp(op, "modsub") == 0)
        ok = p_BN_mod_sub(r, a, b, m, ctx);
    else if (strcmp(op, "modmul") == 0)
        ok = p_BN_mod_mul(r, a, b, m, ctx);
    if (ok == 1) {
        print_bn32(r);
    } else {
        printf(" failed");
    }
    p_BN_free(r);
    p_BN_free(a);
    p_BN_free(b);
    p_BN_free(m);
    p_BN_CTX_free(ctx);
}

static void op_modinv(char **arg, int count)
{
    BN_CTX *ctx;
    BIGNUM *m, *a, *r;
    if (count != 2)
        die("modinv arity");
    ctx = p_BN_CTX_new();
    m = bn_from_hex(arg[0]);
    a = bn_from_hex(arg[1]);
    r = p_BN_new();
    if (ctx == NULL || m == NULL || a == NULL || r == NULL)
        die("modinv allocation failed");
    if (p_BN_mod_inverse(r, a, m, ctx) == NULL) {
        printf(" failed");
    } else {
        print_bn32(r);
    }
    p_BN_free(r);
    p_BN_free(a);
    p_BN_free(m);
    p_BN_CTX_free(ctx);
}

static void op_modexp(char **arg, int count)
{
    BN_CTX *ctx;
    BIGNUM *m, *a, *e, *r;
    int ok;
    if (count != 3)
        die("modexp arity");
    ctx = p_BN_CTX_new();
    m = bn_from_hex(arg[0]);
    a = bn_from_hex(arg[1]);
    e = bn_from_hex(arg[2]);
    r = p_BN_new();
    if (ctx == NULL || m == NULL || a == NULL || e == NULL || r == NULL)
        die("modexp allocation failed");
    ok = p_BN_mod_exp(r, a, e, m, ctx);
    if (ok == 1) {
        print_bn32(r);
    } else {
        printf(" failed");
    }
    p_BN_free(r);
    p_BN_free(a);
    p_BN_free(e);
    p_BN_free(m);
    p_BN_CTX_free(ctx);
}

static void op_scalarmul(char **arg, int count)
{
    BN_CTX *ctx;
    EC_KEY *key;
    const EC_GROUP *group;
    EC_POINT *point;
    BIGNUM *k;
    unsigned char octets[65];
    size_t length;
    if (count != 1)
        die("scalarmul arity");
    ctx = p_BN_CTX_new();
    key = new_p256_key();
    group = p_EC_KEY_get0_group(key);
    point = p_EC_POINT_new(group);
    k = bn_from_hex(arg[0]);
    if (ctx == NULL || point == NULL || k == NULL)
        die("scalarmul allocation failed");
    if (p_EC_POINT_mul(group, point, k, NULL, NULL, ctx) != 1) {
        printf(" failed");
    } else {
        length = p_EC_POINT_point2oct(group, point,
                                      POINT_CONVERSION_UNCOMPRESSED,
                                      octets, sizeof(octets), ctx);
        if (length == 0) {
            printf(" failed");
        } else {
            printf(" ");
            print_hex(octets, length);
        }
    }
    p_BN_free(k);
    p_EC_POINT_free(point);
    p_EC_KEY_free(key);
    p_BN_CTX_free(ctx);
}

static void op_ecdsa_sign(char **arg, int count)
{
    BN_CTX *ctx;
    EC_KEY *key;
    BIGNUM *d, *kinv, *r_in;
    const BIGNUM *r_out, *s_out;
    ECDSA_SIG *sig;
    unsigned char digest[256];
    size_t digest_length;
    int verify;
    if (count != 6)
        die("ecdsa_sign arity");
    ctx = p_BN_CTX_new();
    key = new_p256_key();
    digest_length = hex_to_bytes(arg[0], digest, sizeof(digest));
    d = bn_from_hex(arg[1]);
    kinv = bn_from_hex(arg[2]);
    r_in = bn_from_hex(arg[3]);
    if (ctx == NULL || d == NULL || kinv == NULL || r_in == NULL)
        die("ecdsa_sign allocation failed");
    if (p_EC_KEY_set_private_key(key, d) != 1)
        die("EC_KEY_set_private_key failed");
    if (set_public_key(key, ctx, arg[4], arg[5]) != 1)
        die("set_public_key failed");
    sig = p_ECDSA_do_sign_ex(digest, (int)digest_length, kinv, r_in, key);
    if (sig == NULL) {
        printf(" failed");
    } else {
        p_ECDSA_SIG_get0(sig, &r_out, &s_out);
        print_bn32(r_out);
        print_bn32(s_out);
        verify = p_ECDSA_do_verify(digest, (int)digest_length, sig, key);
        printf(" %d", verify);
        p_ECDSA_SIG_free(sig);
    }
    p_BN_free(d);
    p_BN_free(kinv);
    p_BN_free(r_in);
    p_EC_KEY_free(key);
    p_BN_CTX_free(ctx);
}

static void op_ecdsa_verify(char **arg, int count)
{
    BN_CTX *ctx;
    EC_KEY *key;
    ECDSA_SIG *sig;
    BIGNUM *r, *s;
    unsigned char digest[256];
    size_t digest_length;
    int verify;
    if (count != 5)
        die("ecdsa_verify arity");
    ctx = p_BN_CTX_new();
    key = new_p256_key();
    digest_length = hex_to_bytes(arg[0], digest, sizeof(digest));
    r = bn_from_hex(arg[1]);
    s = bn_from_hex(arg[2]);
    if (ctx == NULL || r == NULL || s == NULL)
        die("ecdsa_verify allocation failed");
    if (set_public_key(key, ctx, arg[3], arg[4]) != 1)
        die("set_public_key failed");
    sig = p_ECDSA_SIG_new();
    if (sig == NULL || p_ECDSA_SIG_set0(sig, r, s) != 1)
        die("ECDSA_SIG_set0 failed");
    verify = p_ECDSA_do_verify(digest, (int)digest_length, sig, key);
    printf(" %d", verify);
    p_ECDSA_SIG_free(sig);
    p_EC_KEY_free(key);
    p_BN_CTX_free(ctx);
}

static void op_rsa_private(char **arg, int count)
{
    unsigned char raw[256];
    unsigned char input[256];
    unsigned char output[256];
    size_t length;
    int result;
    if (count != 1)
        die("rsa_private arity");
    if (rsa_key == NULL)
        die("no RSA key loaded");
    memset(raw, 0, sizeof(raw));
    length = hex_to_bytes(arg[0], raw, sizeof(raw));
    memset(input, 0, sizeof(input));
    memcpy(input + sizeof(input) - length, raw, length);
    result = p_RSA_private_encrypt((int)sizeof(input), input, output, rsa_key,
                                   RSA_NO_PADDING);
    if (result != (int)sizeof(output)) {
        printf(" failed");
    } else {
        printf(" ");
        print_hex(output, sizeof(output));
    }
}

static void op_rsa_check(void)
{
    int result;
    if (rsa_key == NULL)
        die("no RSA key loaded");
    result = p_RSA_check_key(rsa_key);
    printf(" %d", result);
}

static void op_sha256(char **arg, int count)
{
    unsigned char data[4096];
    unsigned char digest[32];
    size_t length;
    if (count != 1)
        die("sha256 arity");
    memset(data, 0, sizeof(data));
    length = hex_to_bytes(arg[0], data, sizeof(data));
    if (p_SHA256(data, length, digest) == NULL) {
        printf(" failed");
    } else {
        printf(" ");
        print_hex(digest, sizeof(digest));
    }
}

static int dispatch(const char *id, char **tokens, int count)
{
    const char *op = tokens[0];
    int arg_count = count - 1;
    char **arg = tokens + 1;
    printf("%s ok", id);
    if (strcmp(op, "modadd") == 0 || strcmp(op, "modsub") == 0 ||
        strcmp(op, "modmul") == 0) {
        op_mod(op, arg, arg_count);
    } else if (strcmp(op, "modinv") == 0) {
        op_modinv(arg, arg_count);
    } else if (strcmp(op, "modexp") == 0) {
        op_modexp(arg, arg_count);
    } else if (strcmp(op, "scalarmul") == 0) {
        op_scalarmul(arg, arg_count);
    } else if (strcmp(op, "ecdsa_sign") == 0) {
        op_ecdsa_sign(arg, arg_count);
    } else if (strcmp(op, "ecdsa_verify") == 0) {
        op_ecdsa_verify(arg, arg_count);
    } else if (strcmp(op, "rsa_private") == 0) {
        op_rsa_private(arg, arg_count);
    } else if (strcmp(op, "rsa_check") == 0) {
        op_rsa_check();
    } else if (strcmp(op, "sha256") == 0) {
        op_sha256(arg, arg_count);
    } else {
        printf(" err unknown-op");
    }
    printf("\n");
    return 0;
}

int main(int argc, char **argv)
{
    const char *library = NULL;
    const char *cases = NULL;
    const char *rsa_path = NULL;
    FILE *handle;
    char line[65536];
    Dl_info info;
    int index;

    for (index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--lib") == 0 && index + 1 < argc)
            library = argv[++index];
        else if (strcmp(argv[index], "--cases") == 0 && index + 1 < argc)
            cases = argv[++index];
        else if (strcmp(argv[index], "--rsa-key") == 0 && index + 1 < argc)
            rsa_path = argv[++index];
        else
            die("unknown argument");
    }
    if (library == NULL || cases == NULL)
        die("usage: etp5_harness --lib LIB --cases FILE [--rsa-key FILE]");

    lib_handle = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    if (lib_handle == NULL)
        die(dlerror());
    load_symbols();
    if (dladdr((void *)p_BN_new, &info) != 0 && info.dli_fname != NULL)
        printf("LIB %s\n", info.dli_fname);

    if (rsa_path != NULL)
        rsa_key = load_rsa_key(rsa_path);

    handle = fopen(cases, "r");
    if (handle == NULL)
        die("cannot open case file");
    while (fgets(line, sizeof(line), handle) != NULL) {
        char *tokens[16];
        int count = 0;
        char *save = NULL;
        char *token = strtok_r(line, " \t\r\n", &save);
        if (token == NULL || token[0] == '#')
            continue;
        while (token != NULL && count < 16) {
            tokens[count++] = token;
            token = strtok_r(NULL, " \t\r\n", &save);
        }
        if (count < 2)
            continue;
        dispatch(tokens[0], tokens + 1, count - 1);
    }
    fclose(handle);

    if (rsa_key != NULL)
        p_RSA_free(rsa_key);
    dlclose(lib_handle);
    return 0;
}
