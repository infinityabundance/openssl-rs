/*
 * haz15_harness.c - HAZ-15 differential harness.
 *
 * Loads exactly one libcrypto.so.3 with dlopen(RTLD_NOW | RTLD_LOCAL) and
 * drives the PKCS#1 v1.5 private-decryption entry point for one fixed RSA key
 * in two shapes:
 *
 *   external  - n, e, p, q, dmp1, dmq1, iqmp with d absent, RSA_FLAG_EXT_PKEY
 *               set (the shape an engine-backed key has: the library does not
 *               hold the private exponent);
 *   internal  - the same key with d present.
 *
 * The harness itself is not linked against libcrypto; every entry point is
 * resolved with dlsym, so the same binary drives the converted candidate and
 * the pinned OpenSSL 3.6.4 authority.
 *
 * Four ciphertexts are submitted for each key shape:
 *
 *   valid       00 02 <245 nonzero> 00 <8-byte message>   (valid padding)
 *   bad_type    00 03 <nonzero...>                        (wrong block type)
 *   short_ps    00 02 <4 nonzero> 00 <nonzero...>         (padding < 8 octets)
 *   out_of_range                                          (ciphertext == n)
 *
 * For every case the harness records the return value, the bytes the call
 * wrote (a 64-bit FNV-1a over the whole output buffer and whether the buffer
 * was touched at all), and the drained error queue.
 *
 * Usage:  haz15_harness <libcrypto.so.3> <label>
 * Output: one JSON object per (key shape, case) on stdout.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct rsa_st RSA;
typedef struct bignum_st BIGNUM;
typedef struct bn_ctx_st BN_CTX;

#define RSA_FLAG_EXT_PKEY 0x0020
#define RSA_PKCS1_PADDING 1
#define RSA_MAX_OUT 4096

static void *lib_handle;

static RSA *(*p_RSA_new)(void);
static void (*p_RSA_free)(RSA *);
static int (*p_RSA_set0_key)(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
static int (*p_RSA_set0_factors)(RSA *, BIGNUM *, BIGNUM *);
static int (*p_RSA_set0_crt_params)(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
static void (*p_RSA_set_flags)(RSA *, int);
static int (*p_RSA_size)(const RSA *);
static int (*p_RSA_private_decrypt)(int, const unsigned char *, unsigned char *,
                                    RSA *, int);

static BIGNUM *(*p_BN_new)(void);
static void (*p_BN_free)(BIGNUM *);
static int (*p_BN_hex2bn)(BIGNUM **, const char *);
static BIGNUM *(*p_BN_bin2bn)(const unsigned char *, int, BIGNUM *);
static int (*p_BN_bn2binpad)(const BIGNUM *, unsigned char *, int);
static int (*p_BN_mod_exp)(BIGNUM *, const BIGNUM *, const BIGNUM *,
                           const BIGNUM *, BN_CTX *);
static BN_CTX *(*p_BN_CTX_new)(void);
static void (*p_BN_CTX_free)(BN_CTX *);

static unsigned long (*p_ERR_get_error)(void);
static void (*p_ERR_clear_error)(void);
static void (*p_ERR_error_string_n)(unsigned long, char *, size_t);

static void die(const char *message)
{
    fprintf(stderr, "haz15_harness: %s\n", message);
    exit(2);
}

static void *sym(const char *name)
{
    void *address = dlsym(lib_handle, name);
    if (address == NULL)
        die(name);
    return address;
}

/* The fixed 2048-bit key of forensics/etp5_crypto/vectors/rsa_key.json, so the
 * candidate and the authority see byte-identical inputs. */
static const char *KEY_N = "ce4b7f3843de01e5c23c8f0a3a6fb6ea062da214f32f0f4b14c308796888b143d059f69c86836d00736497e6553badef64f2a8acff862dc123dfc1de83851d3d5966be971a78a8222c1a574b7c84a0bed78ee6b8d3d08dbe5b85f3995094c2d0e11fc5f250e8db5b87d61e5345219c6a38efc625b4ee56cc5013b2504362437d66db9e606b4f4b36816d59ec1add1d3c1879b8cbc5800cefc9bbb5a9d9400adfa776c8c222eee5665e8bdc09d135fa065f9bcb65c041ceed5b43114214a0a45eace1c344734cc9bca73c0e736d8f20f5f806e000134d3bb6f02126f30174d8f0cd10bc15ae320b93902c47e455227ed21b872a52b66929acb51c773c3ba07c63";
static const char *KEY_E = "10001";
static const char *KEY_D = "61ebac2384f3686b2adb9bf9faeaf423f972c7b0b20df0706f16747b4c8735bd3eb4b53e6f0b0b3e5f87ac2284eaa31133158bc33236fa98e6f25b0fc7d5f39f1f4489cb27a1860d5269de6dd25912040445ac76a6f42393ebd5955f7cc46004ce174ada4e557969e4fc59c0a4dbe366f847b80245f3abf7a73af234ef074188f5d800506a5a882b73b29a35461f5f462acdb322a0b6c0204489c6a43bcf12c1acec94d324dad2db94d53229be76890ff70d00a9a6c9971b3cf95c201a48ae29a92143dfa006807860cf916b9f8633dc6b87c92759ec831e610dc97897ddebcd0163afe5c47c85202fc156c5a58b22a62fda072a1ebf433459e34fa0be034a41";
static const char *KEY_P = "d3bbe2ed6ba9ed489e9e4f8aa46b4534031828e73907234a5821ef1e642c0f0448fb761705c5d065d9299daa5de77b2afab3d4fa01176dab929227a81e526e46654f7d3c59b8138911034c2db11700e148ca0e67e2aab5cab563fb006942b6ed30839a42188d41046b2b3f7f23131a2d798bb3327af9f798e1a5c51b8c607aab";
static const char *KEY_Q = "f96c82dc47ada431233e95211b28b0848f8a11526dc8236cb8a725981c45ab122df1516b786cbae3078891665335adf9726d613fdf4434622c974b28364a747cbff5b594fcecd3f7dd206a17c686e90dcf4c2f83f408e36288a74b2ab53dc9d63559579a130a75db3e23f8704942b5c627b981b0f47c504c88b5eb0241568529";
static const char *KEY_DMP1 = "bb542d36ff9d6d2965e50cdcce11763dc94b13cd57404071e33dcab0a9d1ed4b4e42e4bd03c77b54d0e8a7ecf67dfa1411910faa4d52ec1df364ca1f4d0c8332572a17d45050b33ffec45b1ec5e2634deeb78e3d4d66d9c649ebf643ebdd31b8f2c64cb193c54db3da197e693ea004f61ce68399f301bb95107738c7e1cfee57";
static const char *KEY_DMQ1 = "ba3668fc4c07372df84220d436928a366d7386bb237ae7f7a364268d098e79c978c351260b2221e49d1b38724c6d2715b47834c29acd30ce9abbd9408c47c9efd8e078506303ecbc803a52faad1ccba1a3c21d374659dc6913dcd221706e50e1bbb297d44fa2df9a6f2a2bb0a90144f44b74137f2908266afd25d3ee3b197d1";
static const char *KEY_IQMP = "8e4d08a13a4a6f0434ab2f10ee5c532c1d759df71f4db4c157a678ca8c7d709406ace291570da9335736d966c07b8f435fcc85225576672d57badc92f8a276194f8f7836c81bf034e81804a5eee22291df310ecdb79211b61542bcb9f1b318e907bfd97e74521778cd5145ee66981efef8e7181730151ef151973cdd59d73543";

static BIGNUM *mkbn(const char *hex)
{
    BIGNUM *b = NULL;
    if (p_BN_hex2bn(&b, hex) == 0)
        die("BN_hex2bn");
    return b;
}

static void report(const char *label, const char *shape, const char *case_name,
                   int ret, const unsigned char *out, int num)
{
    const unsigned char sentinel = 0xAA;
    uint64_t fnv = 1469598103934665603ULL;
    int unchanged = 1;
    int i;
    unsigned long last = 0;
    int pending = 0;
    unsigned long code;
    char errbuf[256];
    int shown;

    for (i = 0; i < num; i++) {
        fnv ^= out[i];
        fnv *= 1099511628211ULL;
        if (out[i] != sentinel)
            unchanged = 0;
    }

    errbuf[0] = '\0';
    while ((code = p_ERR_get_error()) != 0) {
        last = code;
        pending++;
    }
    if (last != 0)
        p_ERR_error_string_n(last, errbuf, sizeof(errbuf));

    shown = ret > 0 ? ret : 0;
    if (shown > num)
        shown = num;
    if (shown > 32)
        shown = 32;

    printf("{\"impl\":\"%s\",\"key\":\"%s\",\"case\":\"%s\",\"ret\":%d,"
           "\"out_len\":%d,\"out_prefix_hex\":\"",
           label, shape, case_name, ret, shown);
    for (i = 0; i < shown; i++)
        printf("%02x", out[i]);
    printf("\",\"out_fnv64\":\"%016llx\",\"out_unchanged\":%s,"
           "\"err_pending\":%d,\"err_last\":\"%lu\",\"err_text\":\"%s\"}\n",
           (unsigned long long)fnv, unchanged ? "true" : "false",
           pending, last, errbuf);
    (void)pending;
}

static void build_block(unsigned char *block, int num, const char *case_name)
{
    memset(block, 0x11, (size_t)num);
    if (strcmp(case_name, "valid") == 0) {
        static const unsigned char msg[8] = {'H', 'A', 'Z', '1', '5', 'V', 'A', 'L'};
        block[0] = 0x00;
        block[1] = 0x02;
        /* PS is block[2 .. num-9]: all 0x11, nonzero. */
        block[num - 9] = 0x00;
        memcpy(block + num - 8, msg, sizeof(msg));
    } else if (strcmp(case_name, "bad_type") == 0) {
        block[0] = 0x00;
        block[1] = 0x03;
    } else if (strcmp(case_name, "short_ps") == 0) {
        /* Block type is right but the padding string is four octets, below the
         * eight-octet minimum; the separator is at index 6. */
        block[0] = 0x00;
        block[1] = 0x02;
        block[6] = 0x00;
        memset(block + 7, 0x22, (size_t)(num - 7));
    } else {
        die("unknown case");
    }
}

static void run_case(RSA *key, const char *label, const char *shape,
                     const char *case_name, int num, const BIGNUM *n,
                     const BIGNUM *e)
{
    unsigned char block[512];
    unsigned char cbytes[512];
    unsigned char out[RSA_MAX_OUT];
    BIGNUM *m = NULL;
    BIGNUM *c = NULL;
    BN_CTX *ctx = NULL;
    int ret;

    if (num > (int)sizeof(block))
        die("modulus too wide for the harness");
    if (num > RSA_MAX_OUT)
        die("modulus too wide for the output buffer");

    m = p_BN_new();
    c = p_BN_new();
    ctx = p_BN_CTX_new();
    if (m == NULL || c == NULL || ctx == NULL)
        die("BN allocation");

    if (strcmp(case_name, "out_of_range") == 0) {
        if (p_BN_bn2binpad(n, cbytes, num) != num)
            die("encode n");
    } else {
        build_block(block, num, case_name);
        if (p_BN_bin2bn(block, num, m) == NULL)
            die("BN_bin2bn");
        if (p_BN_mod_exp(c, m, e, n, ctx) == 0)
            die("BN_mod_exp");
        if (p_BN_bn2binpad(c, cbytes, num) != num)
            die("encode c");
    }

    memset(out, 0xAA, (size_t)num);
    p_ERR_clear_error();
    ret = p_RSA_private_decrypt(num, cbytes, out, key, RSA_PKCS1_PADDING);
    report(label, shape, case_name, ret, out, num);

    p_BN_CTX_free(ctx);
    p_BN_free(m);
    p_BN_free(c);
}

int main(int argc, char **argv)
{
    RSA *external;
    RSA *internal;
    const char *label;
    int num;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <libcrypto.so.3> <label>\n", argv[0]);
        return 2;
    }
    label = argv[2];

    lib_handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (lib_handle == NULL)
        die(dlerror());
    printf("{\"impl\":\"%s\",\"event\":\"loaded\",\"hazard\":\"HAZ-15\","
           "\"library\":\"%s\"}\n", label, argv[1]);

    p_RSA_new = (RSA * (*)(void)) sym("RSA_new");
    p_RSA_free = (void (*)(RSA *)) sym("RSA_free");
    p_RSA_set0_key = (int (*)(RSA *, BIGNUM *, BIGNUM *, BIGNUM *)) sym("RSA_set0_key");
    p_RSA_set0_factors = (int (*)(RSA *, BIGNUM *, BIGNUM *)) sym("RSA_set0_factors");
    p_RSA_set0_crt_params = (int (*)(RSA *, BIGNUM *, BIGNUM *, BIGNUM *)) sym("RSA_set0_crt_params");
    p_RSA_set_flags = (void (*)(RSA *, int)) sym("RSA_set_flags");
    p_RSA_size = (int (*)(const RSA *)) sym("RSA_size");
    p_RSA_private_decrypt = (int (*)(int, const unsigned char *, unsigned char *, RSA *, int)) sym("RSA_private_decrypt");

    p_BN_new = (BIGNUM * (*)(void)) sym("BN_new");
    p_BN_free = (void (*)(BIGNUM *)) sym("BN_free");
    p_BN_hex2bn = (int (*)(BIGNUM **, const char *)) sym("BN_hex2bn");
    p_BN_bin2bn = (BIGNUM * (*)(const unsigned char *, int, BIGNUM *)) sym("BN_bin2bn");
    p_BN_bn2binpad = (int (*)(const BIGNUM *, unsigned char *, int)) sym("BN_bn2binpad");
    p_BN_mod_exp = (int (*)(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *)) sym("BN_mod_exp");
    p_BN_CTX_new = (BN_CTX * (*)(void)) sym("BN_CTX_new");
    p_BN_CTX_free = (void (*)(BN_CTX *)) sym("BN_CTX_free");

    p_ERR_get_error = (unsigned long (*)(void)) sym("ERR_get_error");
    p_ERR_clear_error = (void (*)(void)) sym("ERR_clear_error");
    p_ERR_error_string_n = (void (*)(unsigned long, char *, size_t)) sym("ERR_error_string_n");

    /* ---- the external-key shape: n, e, p, q, dmp1, dmq1, iqmp and no d ---- */
    external = p_RSA_new();
    if (external == NULL)
        die("RSA_new external");
    if (p_RSA_set0_key(external, mkbn(KEY_N), mkbn(KEY_E), NULL) != 1)
        die("RSA_set0_key external");
    if (p_RSA_set0_factors(external, mkbn(KEY_P), mkbn(KEY_Q)) != 1)
        die("RSA_set0_factors external");
    if (p_RSA_set0_crt_params(external, mkbn(KEY_DMP1), mkbn(KEY_DMQ1), mkbn(KEY_IQMP)) != 1)
        die("RSA_set0_crt_params external");
    p_RSA_set_flags(external, RSA_FLAG_EXT_PKEY);

    /* ---- the internal-key shape: the same key with d present ---- */
    internal = p_RSA_new();
    if (internal == NULL)
        die("RSA_new internal");
    if (p_RSA_set0_key(internal, mkbn(KEY_N), mkbn(KEY_E), mkbn(KEY_D)) != 1)
        die("RSA_set0_key internal");
    if (p_RSA_set0_factors(internal, mkbn(KEY_P), mkbn(KEY_Q)) != 1)
        die("RSA_set0_factors internal");
    if (p_RSA_set0_crt_params(internal, mkbn(KEY_DMP1), mkbn(KEY_DMQ1), mkbn(KEY_IQMP)) != 1)
        die("RSA_set0_crt_params internal");

    num = p_RSA_size(external);
    if (num <= 0)
        die("RSA_size");

    {
        const char *cases[] = {"valid", "bad_type", "short_ps", "out_of_range"};
        BIGNUM *n = mkbn(KEY_N);
        BIGNUM *e = mkbn(KEY_E);
        size_t i;

        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            run_case(external, label, "external", cases[i], num, n, e);
            run_case(internal, label, "internal", cases[i], num, n, e);
        }
        p_BN_free(n);
        p_BN_free(e);
    }

    p_RSA_free(external);
    p_RSA_free(internal);
    return 0;
}
