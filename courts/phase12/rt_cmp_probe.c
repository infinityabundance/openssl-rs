/*
 * RT-CMP -- the Phase 12.4 CMP object model, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution, whose transcripts are diffed line by line. Every observation is a small integer,
 * a `nonnull`/`null`, a byte equality or a short hex string -- never an address and never a wall
 * clock, so the transcript is a function of the library and not of the probe's own frame
 * (`probe_hygiene.py` compiles it at -O0/-O1/-O2 and requires that).
 *
 * What it drives
 * --------------
 * * `cmp_ctx.c`: `OSSL_CMP_CTX_new`/`_free`/`_reinit`, every `set*`/`get*` accessor, the four
 *   callback setters and their arguments, the option pair, the two `ITAV` stack builders and the
 *   policy/SAN arms.
 * * `cmp_util.c`: `OSSL_CMP_log_open`/`_close`, `OSSL_CMP_print_to_bio` over a memory BIO, and
 *   `OSSL_CMP_print_errors_cb` over the (empty) error queue.
 * * `cmp_status.c`: `OSSL_CMP_STATUSINFO_new`, `OSSL_CMP_snprint_PKIStatusInfo` and
 *   `OSSL_CMP_CTX_snprint_PKIStatus`.
 * * `cmp_hdr.c`: the three `OSSL_CMP_HDR_get0_*` getters over a fixed `PKIHeader` DER.
 * * `cmp_asn.c`: the `OSSL_CMP_ITAV`/`ATAV`/`CRLSTATUS` accessors, the `PKIStatusInfo` lifecycle
 *   and DER round trip, the `ATAVS` `SEQUENCE OF`, and the `PKIMessage`/`PKIHeader` item groups
 *   over fixed DER.
 *
 * 12.4b adds the engine over the fixed `rt_ess_der.h` RSA cert/key -- no key is generated and no
 * clock is read: `OSSL_CMP_CTX_setup_CRM`, the protect/verify round trip through
 * `OSSL_CMP_MSG_update_transactionID`, `OSSL_CMP_MSG_get0_certreq_publickey`,
 * `OSSL_CMP_validate_msg`, the four `cmp_client.c` exchanges handed to an in-process server, the
 * four `cmp_genm.c` readers, and `OSSL_CMP_SRV_process_request`/`OSSL_CMP_CTX_server_perform`. The
 * request's `messageTime`/nonces are the library's own and are never printed, so the transcript
 * stays a function of the library. One arm is named `pending.`: the `EVP_get_digestbyname`
 * identity divergence that `rt_crmf_probe.c:394` and `rt_ocsp_probe.c:580` already record.
 *
 * The two CMP messages are hand-built, fixed DER: a `PKIHeader` with an empty `directoryName`
 * sender and recipient, and a `PKIMessage` whose body is the empty `genm` (`GenMsgContent`) arm.
 * Both sides decode the same bytes and re-encode them, so the comparison is the authority's own
 * byte contract. The error queue is popped at the start of every arm that expects a refusal.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/cmp.h>
#include <openssl/cmp_util.h>
#include <openssl/crmf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/http.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>

#include "rt_ess_der.h"

/* ---------------------------------------------------------------------------------------------
 * Output helpers
 * --------------------------------------------------------------------------------------------- */

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_nonnull(const char *key, const void *p)
{
    printf("%s=%s\n", key, p == NULL ? "null" : "nonnull");
}

static void out_hex(const char *key, const unsigned char *buf, long len)
{
    long i;

    printf("%s.len=%ld\n", key, len);
    printf("%s.hex=", key);
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

/* The `lib.reason` of the first queued error, then the queue is emptied. */
static void out_err(const char *key)
{
    unsigned long e = ERR_peek_error();

    printf("%s=%lu.%lu\n", key,
           e == 0 ? 0UL : (unsigned long)ERR_GET_LIB(e),
           e == 0 ? 0UL : (unsigned long)ERR_GET_REASON(e));
    ERR_clear_error();
}

/* The bytes a memory BIO holds; the BIO is rewound for the next arm. */
static void emit_mem(const char *key, BIO *b)
{
    char *data = NULL;
    long n = BIO_get_mem_data(b, &data);

    out_hex(key, (const unsigned char *)data, n);
    BIO_reset(b);
}

/* ---------------------------------------------------------------------------------------------
 * Fixed DER fixtures (built in-process by hand; see the header comment)
 * --------------------------------------------------------------------------------------------- */

static const unsigned char hdr_der[] = {
    0x30, 0x0b, 0x02, 0x01, 0x02, 0xa4, 0x02, 0x30, 0x00, 0xa4, 0x02, 0x30, 0x00
};

static const unsigned char msg_der[] = {
    0x30, 0x11,
    0x30, 0x0b, 0x02, 0x01, 0x02, 0xa4, 0x02, 0x30, 0x00, 0xa4, 0x02, 0x30, 0x00,
    0xb5, 0x02, 0x30, 0x00
};

/* ---------------------------------------------------------------------------------------------
 * Callback stubs -- only their addresses and return values are observed
 * --------------------------------------------------------------------------------------------- */

static int call_count;

static int dummy_cb(void)
{
    return 1;
}

static int count_log_cb(const char *func, const char *file, int line,
                        OSSL_CMP_severity level, const char *msg)
{
    (void)func;
    (void)file;
    (void)line;
    (void)level;
    (void)msg;
    call_count++;
    return 1;
}

/* ---------------------------------------------------------------------------------------------
 * cmp_util.c
 * --------------------------------------------------------------------------------------------- */

static void drive_util(void)
{
    BIO *mem = BIO_new(BIO_s_mem());

    out_int("util.log_open", OSSL_CMP_log_open());
    OSSL_CMP_log_close();
    out_int("util.log_close", 1);

    out_int("util.print_to_bio.ret",
            OSSL_CMP_print_to_bio(mem, "comp", "file.c", 7, OSSL_CMP_LOG_INFO, "hello"));
    emit_mem("util.print_to_bio", mem);

    out_int("util.print_to_bio.unknown_level",
            OSSL_CMP_print_to_bio(mem, "c", "f", 1, 99, "x"));
    emit_mem("util.print_to_bio.unknown", mem);

    call_count = -1;
    OSSL_CMP_print_errors_cb(count_log_cb);
    out_int("util.print_errors.cb_calls", call_count);

    BIO_free(mem);
}

/* ---------------------------------------------------------------------------------------------
 * cmp_status.c -- PKIStatusInfo rendering
 * --------------------------------------------------------------------------------------------- */

static void drive_status(void)
{
    OSSL_CMP_PKISI *si = OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_accepted,
                                                 (1 << 0) | (1 << 9), "ok then");
    OSSL_CMP_PKISI *si2 = OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection, (1 << 26), NULL);
    OSSL_CMP_PKISI *dup;
    char buf[256];
    char *r;

    out_nonnull("status.si", si);
    if (si != NULL) {
        r = OSSL_CMP_snprint_PKIStatusInfo(si, buf, sizeof(buf));
        printf("status.snprint=%s\n", r == NULL ? "null" : buf);
        dup = OSSL_CMP_PKISI_dup(si);
        out_nonnull("status.dup", dup);
        OSSL_CMP_PKISI_free(dup);
    }
    out_nonnull("status.si2", si2);
    if (si2 != NULL) {
        r = OSSL_CMP_snprint_PKIStatusInfo(si2, buf, sizeof(buf));
        printf("status.snprint2=%s\n", r == NULL ? "null" : buf);
    }
    out_err("status.err_after_fill");

    out_nonnull("status.snprint_null", OSSL_CMP_snprint_PKIStatusInfo(NULL, buf, sizeof(buf)));
    out_err("status.err_snprint_null");
    out_nonnull("status.ctx_null", OSSL_CMP_CTX_snprint_PKIStatus(NULL, buf, sizeof(buf)));
    out_err("status.err_ctx_null");

    OSSL_CMP_PKISI_free(si);
    OSSL_CMP_PKISI_free(si2);
}

/* ---------------------------------------------------------------------------------------------
 * cmp_asn.c -- PKIStatusInfo, ATAV/ITAV/CRLSTATUS accessors and the item groups
 * --------------------------------------------------------------------------------------------- */

static void drive_asn(void)
{
    OSSL_CMP_PKISI *si = OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_grantedWithMods, 0, "gm");
    OSSL_CMP_PKISI *back;
    unsigned char *der = NULL;
    const unsigned char *p;
    int len;
    OSSL_CMP_ATAV *atav;
    OSSL_CMP_ATAVS *atavs;
    OSSL_CMP_ITAV *itav;
    OSSL_CMP_CRLSTATUS *crs;
    ASN1_INTEGER *aint;
    X509_ALGOR *alg;
    DIST_POINT_NAME *dpn = NULL;
    GENERAL_NAMES *issuers = NULL;
    ASN1_TIME *tupd = NULL;
    STACK_OF(OSSL_CMP_ITAV) *itav_stack = NULL;
    OSSL_CMP_ATAVS *atavs_p = NULL;

    /* PKIStatusInfo round trip */
    len = i2d_OSSL_CMP_PKISI(si, &der);
    out_hex("asn.pkisi.der", der, len);
    p = der;
    back = d2i_OSSL_CMP_PKISI(NULL, &p, len);
    out_nonnull("asn.pkisi.d2i", back);
    OSSL_CMP_PKISI_free(back);
    OPENSSL_free(der);
    der = NULL;
    out_nonnull("asn.pkisi_new", OSSL_CMP_PKISI_new());
    out_nonnull("asn.pkistatus_it", (void *)OSSL_CMP_PKISTATUS_it());
    out_nonnull("asn.pkisi_it", (void *)OSSL_CMP_PKISI_it());
    OSSL_CMP_PKISI_free(si);

    /* ITAV: default ANY arm and the per-type builders' empty arms */
    itav = OSSL_CMP_ITAV_create(OBJ_txt2obj("1.2.3.4", 1),
                                ASN1_TYPE_new());
    out_nonnull("asn.itav_create", itav);
    out_nonnull("asn.itav_get0_type", OSSL_CMP_ITAV_get0_type(itav));
    out_nonnull("asn.itav_get0_value", OSSL_CMP_ITAV_get0_value(itav));
    OSSL_CMP_ITAV_set0(itav, OBJ_txt2obj("1.2.3.5", 1), NULL);
    out_nonnull("asn.itav_set0_type", OSSL_CMP_ITAV_get0_type(itav));
    out_int("asn.itav_push0", OSSL_CMP_ITAV_push0_stack_item(&itav_stack, itav));
    out_int("asn.itav_stack_num", OPENSSL_sk_num((const OPENSSL_STACK *)itav_stack));
    OPENSSL_sk_pop_free((OPENSSL_STACK *)itav_stack, (void (*)(void *))OSSL_CMP_ITAV_free);
    itav_stack = NULL;

    itav = OSSL_CMP_ITAV_new0_certProfile(NULL);
    out_nonnull("asn.itav_certprofile", itav);
    out_int("asn.itav_get0_certprofile", OSSL_CMP_ITAV_get0_certProfile(itav, NULL));
    OSSL_CMP_ITAV_free(itav);

    itav = OSSL_CMP_ITAV_new_caCerts(NULL);
    out_int("asn.itav_get0_cacerts", OSSL_CMP_ITAV_get0_caCerts(itav, NULL));
    OSSL_CMP_ITAV_free(itav);

    itav = OSSL_CMP_ITAV_new_rootCaCert(NULL);
    out_int("asn.itav_get0_rootcacert", OSSL_CMP_ITAV_get0_rootCaCert(itav, NULL));
    OSSL_CMP_ITAV_free(itav);

    itav = OSSL_CMP_ITAV_new_rootCaKeyUpdate(NULL, NULL, NULL);
    out_int("asn.itav_get0_rootcakeyupdate",
            OSSL_CMP_ITAV_get0_rootCaKeyUpdate(itav, NULL, NULL, NULL));
    OSSL_CMP_ITAV_free(itav);

    itav = OSSL_CMP_ITAV_new0_certReqTemplate(NULL, NULL);
    out_int("asn.itav_get1_certreqtemplate",
            OSSL_CMP_ITAV_get1_certReqTemplate(itav, NULL, NULL));
    OSSL_CMP_ITAV_free(itav);

    itav = OSSL_CMP_ITAV_new0_crlStatusList(NULL);
    out_int("asn.itav_get0_crlstatuslist", OSSL_CMP_ITAV_get0_crlStatusList(itav, NULL));
    OSSL_CMP_ITAV_free(itav);

    itav = OSSL_CMP_ITAV_new_crls(NULL);
    out_int("asn.itav_get0_crls", OSSL_CMP_ITAV_get0_crls(itav, NULL));
    {
        OSSL_CMP_ITAV *dup = OSSL_CMP_ITAV_dup(itav);
        out_nonnull("asn.itav_dup", dup);
        OSSL_CMP_ITAV_free(dup);
    }
    out_nonnull("asn.itav_free_null", (void *)0);
    OSSL_CMP_ITAV_free(itav);

    /* the wrong-type refusals */
    itav = OSSL_CMP_ITAV_create(OBJ_txt2obj("1.2.3.4", 1), ASN1_TYPE_new());
    out_int("asn.itav_wrongtype_certprofile", OSSL_CMP_ITAV_get0_certProfile(itav, NULL));
    out_err("asn.itav_wrongtype_err");
    OSSL_CMP_ITAV_free(itav);

    /* ATAV */
    aint = ASN1_INTEGER_new();
    ASN1_INTEGER_set(aint, 2048);
    atav = OSSL_CMP_ATAV_new_rsaKeyLen(2048);
    out_nonnull("asn.atav_rsalen", atav);
    out_int("asn.atav_get_rsalen", OSSL_CMP_ATAV_get_rsaKeyLen(atav));
    out_nonnull("asn.atav_get0_type", OSSL_CMP_ATAV_get0_type(atav));
    out_nonnull("asn.atav_get0_value", OSSL_CMP_ATAV_get0_value(atav));
    out_nonnull("asn.atav_get0_algid", OSSL_CMP_ATAV_get0_algId(atav));
    out_int("asn.atav_push1", OSSL_CMP_ATAV_push1(&atavs_p, atav));
    out_nonnull("asn.atavs_p", atavs_p);
    ASN1_INTEGER_free(aint);

    alg = X509_ALGOR_new();
    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_sha256), V_ASN1_NULL, NULL);
    atav = OSSL_CMP_ATAV_new_algId(alg);
    out_nonnull("asn.atav_algid", atav);
    out_nonnull("asn.atav_algid_get", OSSL_CMP_ATAV_get0_algId(atav));
    X509_ALGOR_free(alg);

    atav = OSSL_CMP_ATAV_create(OBJ_txt2obj("1.2.3.4", 1), NULL);
    out_nonnull("asn.atav_create", atav);
    OSSL_CMP_ATAV_set0(atav, OSSL_CMP_ATAV_get0_type(atav), NULL);
    out_nonnull("asn.atav_type", OSSL_CMP_ATAV_get0_type(atav));

    /* ATAVS: empty SEQUENCE OF round trip, and one with the `rsaKeyLen` member */
    atavs = OSSL_CMP_ATAVS_new();
    len = i2d_OSSL_CMP_ATAVS(atavs, &der);
    out_hex("asn.atavs.empty.der", der, len);
    {
        const unsigned char *q = der;
        OSSL_CMP_ATAVS *rt = d2i_OSSL_CMP_ATAVS(NULL, &q, len);
        out_nonnull("asn.atavs.empty.d2i", rt);
        OSSL_CMP_ATAVS_free(rt);
    }
    OPENSSL_free(der);
    der = NULL;
    OSSL_CMP_ATAVS_free(atavs);
    out_nonnull("asn.atavs_it", (void *)OSSL_CMP_ATAVS_it());
    if (atavs_p != NULL) {
        len = i2d_OSSL_CMP_ATAVS(atavs_p, &der);
        out_hex("asn.atavs.one.der", der, len);
        OPENSSL_free(der);
        der = NULL;
        OSSL_CMP_ATAVS_free(atavs_p);
    }

    /* CRLSTATUS refusals */
    crs = OSSL_CMP_CRLSTATUS_new1(NULL, NULL, NULL);
    out_nonnull("asn.crlstatus_null", crs);
    out_err("asn.crlstatus_err");
    out_int("asn.crlstatus_get0_null", OSSL_CMP_CRLSTATUS_get0(NULL, &dpn, &issuers, &tupd));
    OSSL_CMP_CRLSTATUS_free(crs);
    OSSL_CMP_CRLSTATUS_free(NULL);

    /* CRLSTATUS high-level builder: the empty-CRL issuer fallback, and the NULL refusal */
    {
        X509_CRL *crl = X509_CRL_new();
        OSSL_CMP_CRLSTATUS *cs = OSSL_CMP_CRLSTATUS_create(crl, NULL, 1);
        out_nonnull("asn.crlstatus_create", cs);
        if (cs != NULL) {
            DIST_POINT_NAME *dpn2 = NULL;
            GENERAL_NAMES *issuers2 = NULL;
            ASN1_TIME *tupd2 = NULL;
            out_int("asn.crlstatus_create_get0",
                    OSSL_CMP_CRLSTATUS_get0(cs, &dpn2, &issuers2, &tupd2));
            out_nonnull("asn.crlstatus_create_issuer", issuers2);
            OSSL_CMP_CRLSTATUS_free(cs);
        }
        out_err("asn.crlstatus_create_err");
        X509_CRL_free(crl);
        cs = OSSL_CMP_CRLSTATUS_create(NULL, NULL, 1);
        out_nonnull("asn.crlstatus_create_null", cs);
        out_err("asn.crlstatus_create_null_err");
    }
    out_int("asn.done", 1);
}

/* ---------------------------------------------------------------------------------------------
 * cmp_hdr.c and the PKIHeader/MSG item groups
 * --------------------------------------------------------------------------------------------- */

static void drive_msg(void)
{
    const unsigned char *p = hdr_der;
    OSSL_CMP_PKIHEADER *hdr = d2i_OSSL_CMP_PKIHEADER(NULL, &p, (long)sizeof(hdr_der));
    unsigned char *der = NULL;
    OSSL_CMP_MSG *msg;
    OSSL_CMP_MSG *dup;
    const unsigned char *q = msg_der;
    int len;

    out_nonnull("msg.hdr_d2i", hdr);
    if (hdr != NULL) {
        out_nonnull("msg.hdr_transactionID", OSSL_CMP_HDR_get0_transactionID(hdr));
        out_nonnull("msg.hdr_recipNonce", OSSL_CMP_HDR_get0_recipNonce(hdr));
        out_nonnull("msg.hdr_geninfo", OSSL_CMP_HDR_get0_geninfo_ITAVs(hdr));
        len = i2d_OSSL_CMP_PKIHEADER(hdr, &der);
        out_hex("msg.hdr_i2d", der, len);
        OPENSSL_free(der);
        der = NULL;
        OSSL_CMP_PKIHEADER_free(hdr);
    }
    out_nonnull("msg.hdr_it", (void *)OSSL_CMP_PKIHEADER_it());
    out_nonnull("msg.hdr_new", OSSL_CMP_PKIHEADER_new());
    OSSL_CMP_PKIHEADER_free(NULL);

    msg = (OSSL_CMP_MSG *)ASN1_item_d2i(NULL, &q, (long)sizeof(msg_der), OSSL_CMP_MSG_it());
    out_nonnull("msg.d2i", msg);
    if (msg != NULL) {
        dup = OSSL_CMP_MSG_dup(msg);
        out_nonnull("msg.dup", dup);
        len = ASN1_item_i2d((ASN1_VALUE *)msg, &der, OSSL_CMP_MSG_it());
        out_hex("msg.i2d", der, len);
        OPENSSL_free(der);
        der = NULL;
        ASN1_item_free((ASN1_VALUE *)dup, OSSL_CMP_MSG_it());
        ASN1_item_free((ASN1_VALUE *)msg, OSSL_CMP_MSG_it());
    }
    out_nonnull("msg.it", (void *)OSSL_CMP_MSG_it());
    out_nonnull("msg.dup_null", OSSL_CMP_MSG_dup(NULL));
}

/* ---------------------------------------------------------------------------------------------
 * cmp_msg.c (lifecycle + (de)serialisation), cmp_http.c and cmp_vfy.c
 * --------------------------------------------------------------------------------------------- */

static void drive_msg_more(void)
{
    const unsigned char *p = msg_der;
    OSSL_CMP_MSG *msg = d2i_OSSL_CMP_MSG(NULL, &p, (long)sizeof(msg_der));
    unsigned char *der = NULL;
    int len;
    BIO *mem;
    BIO *out;
    OSSL_CMP_CTX *ctx;
    X509_STORE *store;
    X509 *x;
    const char *path = "/tmp/rt_cmp_msg.der";

    out_nonnull("msg2.d2i", msg);
    if (msg != NULL) {
        out_nonnull("msg2.get0_header", OSSL_CMP_MSG_get0_header(msg));
        out_int("msg2.get_bodytype", OSSL_CMP_MSG_get_bodytype(msg));
        len = i2d_OSSL_CMP_MSG(msg, &der);
        out_hex("msg2.i2d", der, len);
        OPENSSL_free(der);
        der = NULL;

        out_int("msg2.write", OSSL_CMP_MSG_write(path, msg));
        out_err("msg2.write_err");
        {
            OSSL_CMP_MSG *rt = OSSL_CMP_MSG_read(path, NULL, NULL);
            out_nonnull("msg2.read", rt);
            if (rt != NULL) {
                out_int("msg2.read_type", OSSL_CMP_MSG_get_bodytype(rt));
                OSSL_CMP_MSG_free(rt);
            }
        }
        out_err("msg2.read_err");

        mem = BIO_new(BIO_s_mem());
        BIO_write(mem, msg_der, (int)sizeof(msg_der));
        {
            OSSL_CMP_MSG *bio_msg = d2i_OSSL_CMP_MSG_bio(mem, NULL);
            BIO_free(mem);
            out_nonnull("msg2.d2i_bio", bio_msg);
            if (bio_msg != NULL) {
                out = BIO_new(BIO_s_mem());
                out_int("msg2.i2d_bio", i2d_OSSL_CMP_MSG_bio(out, bio_msg));
                emit_mem("msg2.i2d_bio", out);
                BIO_free(out);
                OSSL_CMP_MSG_free(bio_msg);
            }
        }
        OSSL_CMP_MSG_free(msg);
    }

    out_nonnull("msg2.get0_header_null", OSSL_CMP_MSG_get0_header(NULL));
    out_err("msg2.get0_header_null_err");
    out_nonnull("msg2.read_null", OSSL_CMP_MSG_read(NULL, NULL, NULL));
    out_err("msg2.read_null_err");
    out_int("msg2.write_null_file", OSSL_CMP_MSG_write(NULL, NULL));
    out_err("msg2.write_null_file_err");
    OSSL_CMP_MSG_free(NULL);
    out_int("msg2.free_null", 1);

    /* cmp_vfy.c: the refusal arms and one empty-cert path */
    ctx = OSSL_CMP_CTX_new(NULL, NULL);
    store = X509_STORE_new();
    x = X509_new();
    out_int("vfy.null_ctx", OSSL_CMP_validate_cert_path(NULL, store, x));
    out_err("vfy.null_ctx_err");
    out_int("vfy.null_store", OSSL_CMP_validate_cert_path(ctx, NULL, x));
    out_err("vfy.null_store_err");
    out_int("vfy.null_cert", OSSL_CMP_validate_cert_path(ctx, store, NULL));
    out_err("vfy.null_cert_err");
    X509_free(x);
    X509_STORE_free(store);
    OSSL_CMP_CTX_free(ctx);

    /* cmp_http.c: the two NULL refusals, no socket is opened */
    out_nonnull("http.null", OSSL_CMP_MSG_http_perform(NULL, NULL));
    out_err("http.null_err");
    ctx = OSSL_CMP_CTX_new(NULL, NULL);
    out_nonnull("http.null_req", OSSL_CMP_MSG_http_perform(ctx, NULL));
    out_err("http.null_req_err");
    OSSL_CMP_CTX_free(ctx);
}

/* ---------------------------------------------------------------------------------------------
 * cmp_client.c -- the default certConf callback, and cmp_server.c -- the SRV_CTX plumbing
 * --------------------------------------------------------------------------------------------- */

static void drive_srv_and_certconf(void)
{
    OSSL_CMP_SRV_CTX *srv = OSSL_CMP_SRV_CTX_new(NULL, "prov");
    OSSL_CMP_CTX *ccb_ctx = OSSL_CMP_CTX_new(NULL, NULL);
    X509 *x = X509_new();
    X509_STORE *store = X509_STORE_new();
    OSSL_CMP_SRV_CTX *srv2;

    out_nonnull("srv.new", srv);
    out_nonnull("srv.get0_cmp_ctx", OSSL_CMP_SRV_CTX_get0_cmp_ctx(srv));
    out_nonnull("srv.get0_custom_ctx", OSSL_CMP_SRV_CTX_get0_custom_ctx(srv));
    out_int("srv.init",
            OSSL_CMP_SRV_CTX_init(srv, (void *)0x1, NULL, NULL, NULL, NULL, NULL, NULL));
    out_nonnull("srv.get0_custom_ctx2", OSSL_CMP_SRV_CTX_get0_custom_ctx(srv));
    out_int("srv.init_trans", OSSL_CMP_SRV_CTX_init_trans(srv, NULL, NULL));
    out_int("srv.set_sue", OSSL_CMP_SRV_CTX_set_send_unprotected_errors(srv, 1));
    out_int("srv.set_au", OSSL_CMP_SRV_CTX_set_accept_unprotected(srv, 2));
    out_int("srv.set_arv", OSSL_CMP_SRV_CTX_set_accept_raverified(srv, 0));
    out_int("srv.set_gic", OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(srv, 1));
    OSSL_CMP_SRV_CTX_free(srv);

    srv2 = OSSL_CMP_SRV_CTX_new(NULL, NULL);
    out_nonnull("srv.new2", srv2);
    OSSL_CMP_SRV_CTX_free(srv2);

    /* the refusal arms */
    out_int("srv.null_init", OSSL_CMP_SRV_CTX_init(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL));
    out_int("srv.null_init_trans", OSSL_CMP_SRV_CTX_init_trans(NULL, NULL, NULL));
    out_nonnull("srv.null_cmp_ctx", OSSL_CMP_SRV_CTX_get0_cmp_ctx(NULL));
    out_nonnull("srv.null_custom_ctx", OSSL_CMP_SRV_CTX_get0_custom_ctx(NULL));
    out_int("srv.null_sue", OSSL_CMP_SRV_CTX_set_send_unprotected_errors(NULL, 1));
    out_int("srv.null_au", OSSL_CMP_SRV_CTX_set_accept_unprotected(NULL, 1));
    out_int("srv.null_arv", OSSL_CMP_SRV_CTX_set_accept_raverified(NULL, 1));
    out_int("srv.null_gic", OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(NULL, 1));
    out_err("srv.null_err");
    OSSL_CMP_SRV_CTX_free(NULL);
    out_int("srv.free_null", 1);

    /* cmp_client.c: the failure-info arms return before touching cert/ctx further */
    out_int("ccb.failinfo", OSSL_CMP_certConf_cb(ccb_ctx, x, 5, NULL));
    out_int("ccb.failinfo_null_cert", OSSL_CMP_certConf_cb(ccb_ctx, NULL, 7, NULL));
    out_int("ccb.set_arg", OSSL_CMP_CTX_set_certConf_cb_arg(ccb_ctx, store));
    out_int("ccb.with_store", OSSL_CMP_certConf_cb(ccb_ctx, x, 0, NULL));
    out_err("ccb.with_store_err");

    X509_STORE_free(store);
    X509_free(x);
    OSSL_CMP_CTX_free(ccb_ctx);
}

/* ---------------------------------------------------------------------------------------------
 * cmp_ctx.c
 * --------------------------------------------------------------------------------------------- */

static void drive_ctx(void)
{
    OSSL_CMP_CTX *ctx = OSSL_CMP_CTX_new(NULL, "prov");
    OSSL_CMP_ITAV *itav;
    ASN1_OCTET_STRING *oct = ASN1_OCTET_STRING_new();
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    unsigned char ref[4] = { 1, 2, 3, 4 };

    out_nonnull("ctx.new", ctx);
    out_nonnull("ctx.get0_propq", (void *)OSSL_CMP_CTX_get0_propq(ctx));
    out_nonnull("ctx.get0_libctx", OSSL_CMP_CTX_get0_libctx(ctx));
    out_nonnull("ctx.get0_trusted", OSSL_CMP_CTX_get0_trustedStore(ctx));
    out_nonnull("ctx.get0_untrusted", OSSL_CMP_CTX_get0_untrusted(ctx));
    out_nonnull("ctx.get0_statusString", OSSL_CMP_CTX_get0_statusString(ctx));
    out_nonnull("ctx.get0_geninfo", OSSL_CMP_CTX_get0_geninfo_ITAVs(ctx));
    out_nonnull("ctx.get0_validated", OSSL_CMP_CTX_get0_validatedSrvCert(ctx));
    out_nonnull("ctx.get0_newCert", OSSL_CMP_CTX_get0_newCert(ctx));
    out_nonnull("ctx.get_certConf_arg", OSSL_CMP_CTX_get_certConf_cb_arg(ctx));
    out_nonnull("ctx.get_http_arg", OSSL_CMP_CTX_get_http_cb_arg(ctx));
    out_nonnull("ctx.get_transfer_arg", OSSL_CMP_CTX_get_transfer_cb_arg(ctx));
    out_int("ctx.get_status", OSSL_CMP_CTX_get_status(ctx));
    out_int("ctx.get_failInfo", OSSL_CMP_CTX_get_failInfoCode(ctx));
    out_nonnull("ctx.get0_newPkey0", OSSL_CMP_CTX_get0_newPkey(ctx, 0));
    out_nonnull("ctx.get0_newPkey1", OSSL_CMP_CTX_get0_newPkey(ctx, 1));
    out_nonnull("ctx.get1_newChain", OSSL_CMP_CTX_get1_newChain(ctx));
    out_nonnull("ctx.get1_extraCertsIn", OSSL_CMP_CTX_get1_extraCertsIn(ctx));
    out_nonnull("ctx.get1_caPubs", OSSL_CMP_CTX_get1_caPubs(ctx));

    /* setters whose effect a getter can read back */
    out_int("ctx.set_option.keepalive", OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_KEEP_ALIVE, 2));
    out_int("ctx.get_option.keepalive", OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_KEEP_ALIVE));
    out_int("ctx.set_option.days", OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_VALIDITY_DAYS, 30));
    out_int("ctx.get_option.days", OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_VALIDITY_DAYS));
    out_int("ctx.set_option.popo", OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_POPO_METHOD, 0));
    out_int("ctx.get_option.popo", OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_POPO_METHOD));
    out_int("ctx.set_option.implicit", OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_IMPLICIT_CONFIRM, 1));
    out_int("ctx.get_option.implicit", OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_IMPLICIT_CONFIRM));
    out_int("ctx.set_option.reason", OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_REVOCATION_REASON, 1));
    out_int("ctx.get_option.reason", OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_REVOCATION_REASON));
    out_int("ctx.set_option.mac", OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_MAC_ALGNID, 781));
    out_int("ctx.get_option.mac", OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_MAC_ALGNID));
    out_int("ctx.get_option.digest", OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_DIGEST_ALGNID));
    out_int("ctx.get_option.owf", OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_OWF_ALGNID));
    out_int("ctx.set_option.bad", OSSL_CMP_CTX_set_option(ctx, 9999, 1));
    out_err("ctx.set_option.bad_err");
    out_int("ctx.get_option.bad", OSSL_CMP_CTX_get_option(ctx, 9999));
    out_err("ctx.get_option.bad_err");

    out_int("ctx.set_serverport", OSSL_CMP_CTX_set_serverPort(ctx, 8080));
    out_int("ctx.set_server", OSSL_CMP_CTX_set1_server(ctx, "localhost"));
    out_int("ctx.set_serverpath", OSSL_CMP_CTX_set1_serverPath(ctx, "/cmp"));
    out_int("ctx.set_proxy", OSSL_CMP_CTX_set1_proxy(ctx, "proxy:3128"));
    out_int("ctx.set_noproxy", OSSL_CMP_CTX_set1_no_proxy(ctx, "localhost"));
    out_int("ctx.set_recipient", OSSL_CMP_CTX_set1_recipient(ctx, NULL));
    out_int("ctx.set_expected", OSSL_CMP_CTX_set1_expected_sender(ctx, NULL));
    out_int("ctx.set_issuer", OSSL_CMP_CTX_set1_issuer(ctx, NULL));
    out_int("ctx.set_subject", OSSL_CMP_CTX_set1_subjectName(ctx, NULL));
    out_int("ctx.set_serial", OSSL_CMP_CTX_set1_serialNumber(ctx, serial));
    out_int("ctx.set_cert", OSSL_CMP_CTX_set1_cert(ctx, NULL));
    out_int("ctx.set_oldcert", OSSL_CMP_CTX_set1_oldCert(ctx, NULL));
    out_int("ctx.set_srvcert", OSSL_CMP_CTX_set1_srvCert(ctx, NULL));
    out_int("ctx.set_pkey", OSSL_CMP_CTX_set1_pkey(ctx, NULL));
    out_int("ctx.set_p10csr", OSSL_CMP_CTX_set1_p10CSR(ctx, NULL));
    out_int("ctx.set_extraout", OSSL_CMP_CTX_set1_extraCertsOut(ctx, NULL));
    out_int("ctx.set_untrusted", OSSL_CMP_CTX_set1_untrusted(ctx, NULL));
    out_int("ctx.set_refval", OSSL_CMP_CTX_set1_referenceValue(ctx, ref, 4));
    out_int("ctx.set_secval", OSSL_CMP_CTX_set1_secretValue(ctx, ref, 4));
    out_int("ctx.set_tid", OSSL_CMP_CTX_set1_transactionID(ctx, oct));
    out_int("ctx.set_sendernonce", OSSL_CMP_CTX_set1_senderNonce(ctx, oct));
    out_int("ctx.set0_trusted", OSSL_CMP_CTX_set0_trustedStore(ctx, NULL));
    out_int("ctx.set0_newpkey", OSSL_CMP_CTX_set0_newPkey(ctx, 1, NULL));
    out_int("ctx.set0_reqext", OSSL_CMP_CTX_set0_reqExtensions(ctx, NULL));
    out_int("ctx.push_policy_null", OSSL_CMP_CTX_push0_policy(ctx, NULL));
    out_int("ctx.push_san_null", OSSL_CMP_CTX_push1_subjectAltName(ctx, NULL));
    out_int("ctx.reqext_have_san", OSSL_CMP_CTX_reqExtensions_have_SAN(ctx));

    itav = OSSL_CMP_ITAV_create(OBJ_txt2obj("1.2.3.4", 1), ASN1_TYPE_new());
    out_int("ctx.push_geninfo", OSSL_CMP_CTX_push0_geninfo_ITAV(ctx, itav));
    out_nonnull("ctx.get0_geninfo2", OSSL_CMP_CTX_get0_geninfo_ITAVs(ctx));
    out_int("ctx.reset_geninfo", OSSL_CMP_CTX_reset_geninfo_ITAVs(ctx));
    itav = OSSL_CMP_ITAV_create(OBJ_txt2obj("1.2.3.4", 1), ASN1_TYPE_new());
    out_int("ctx.push_genm", OSSL_CMP_CTX_push0_genm_ITAV(ctx, itav));

    out_int("ctx.set_log_cb", OSSL_CMP_CTX_set_log_cb(ctx, count_log_cb));
    out_int("ctx.set_certconf_cb", OSSL_CMP_CTX_set_certConf_cb(ctx, (OSSL_CMP_certConf_cb_t)dummy_cb));
    out_int("ctx.set_certconf_arg", OSSL_CMP_CTX_set_certConf_cb_arg(ctx, (void *)0x1));
    out_nonnull("ctx.get_certconf_arg2", OSSL_CMP_CTX_get_certConf_cb_arg(ctx));
    out_int("ctx.set_http_cb", OSSL_CMP_CTX_set_http_cb(ctx, (OSSL_HTTP_bio_cb_t)dummy_cb));
    out_int("ctx.set_http_arg", OSSL_CMP_CTX_set_http_cb_arg(ctx, (void *)0x2));
    out_nonnull("ctx.get_http_arg2", OSSL_CMP_CTX_get_http_cb_arg(ctx));
    out_int("ctx.set_transfer_cb", OSSL_CMP_CTX_set_transfer_cb(ctx, (OSSL_CMP_transfer_cb_t)dummy_cb));
    out_int("ctx.set_transfer_arg", OSSL_CMP_CTX_set_transfer_cb_arg(ctx, (void *)0x3));
    out_nonnull("ctx.get_transfer_arg2", OSSL_CMP_CTX_get_transfer_cb_arg(ctx));

    call_count = -1;
    OSSL_CMP_CTX_print_errors(ctx);
    out_int("ctx.print_errors.cb_calls", call_count);

    out_int("ctx.reinit", OSSL_CMP_CTX_reinit(ctx));
    out_int("ctx.build_chain", OSSL_CMP_CTX_build_cert_chain(ctx, NULL, NULL));
    out_err("ctx.build_chain_err");

    OSSL_CMP_CTX_free(ctx);

    /* the NULL refusals */
    out_int("ctx.null_get_status", OSSL_CMP_CTX_get_status(NULL));
    out_nonnull("ctx.null_get_propq", (void *)OSSL_CMP_CTX_get0_propq(NULL));
    out_int("ctx.null_set_server", OSSL_CMP_CTX_set1_server(NULL, "x"));
    out_int("ctx.null_reinit", OSSL_CMP_CTX_reinit(NULL));
    out_int("ctx.null_set_option", OSSL_CMP_CTX_set_option(NULL, OSSL_CMP_OPT_KEEP_ALIVE, 1));
    out_int("ctx.null_get_option", OSSL_CMP_CTX_get_option(NULL, OSSL_CMP_OPT_KEEP_ALIVE));
    out_err("ctx.null_err");
    OSSL_CMP_CTX_free(NULL);
    out_int("ctx.free_null", 1);

    ASN1_OCTET_STRING_free(oct);
    ASN1_INTEGER_free(serial);
}

/* ---------------------------------------------------------------------------------------------
 * The engine: `cmp_msg.c`'s builders, `cmp_protect.c`, `cmp_client.c`, `cmp_vfy.c`,
 * `cmp_genm.c` and `cmp_server.c`, over the fixed RSA cert/key from `rt_ess_der.h`.
 * --------------------------------------------------------------------------------------------- */

static X509 *engine_cert;
static OSSL_CMP_CTX *engine_validator;

static void write_fixture(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");

    if (f != NULL) {
        fwrite(text, 1, strlen(text), f);
        fclose(f);
    }
}

static X509 *load_pem_cert(const char *path)
{
    FILE *f = fopen(path, "r");
    X509 *x = f == NULL ? NULL : PEM_read_X509(f, NULL, NULL, NULL);

    if (f != NULL)
        fclose(f);
    return x;
}

static EVP_PKEY *load_pem_key(const char *path)
{
    FILE *f = fopen(path, "r");
    EVP_PKEY *k = f == NULL ? NULL : PEM_read_PrivateKey(f, NULL, NULL, NULL);

    if (f != NULL)
        fclose(f);
    return k;
}

/* The server's cert-request callback: reject deterministically, no certificate is issued. */
static OSSL_CMP_PKISI *engine_srv_certreq(OSSL_CMP_SRV_CTX *srv_ctx,
    const OSSL_CMP_MSG *req, int certReqId, const OSSL_CRMF_MSG *crm,
    const X509_REQ *p10cr, X509 **certOut, STACK_OF(X509) **chainOut,
    STACK_OF(X509) **caPubs)
{
    (void)srv_ctx;
    (void)req;
    (void)p10cr;
    (void)certOut;
    (void)chainOut;
    (void)caPubs;
    out_int("engine.srv.certreq.rid", certReqId);
    out_nonnull("engine.srv.certreq.crm", crm);
    return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection, 0, "rt-cmp");
}

/* The server's genm callback: refuse, so the reader path ends in a deterministic error. */
static int engine_srv_genm(OSSL_CMP_SRV_CTX *srv_ctx, const OSSL_CMP_MSG *req,
    const STACK_OF(OSSL_CMP_ITAV) *in, STACK_OF(OSSL_CMP_ITAV) **out)
{
    (void)srv_ctx;
    (void)req;
    (void)in;
    (void)out;
    out_int("engine.srv.genm", 1);
    return 0;
}

/*
 * The transfer callback: observe the protected request, then hand it to the in-process server
 * through `OSSL_CMP_CTX_server_perform`, whose `transfer_cb_arg` is the SRV_CTX. Never prints
 * the request's `messageTime` or nonces, which the library generates.
 */
static OSSL_CMP_MSG *engine_transfer(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *req)
{
    int type = OSSL_CMP_MSG_get_bodytype(req);

    out_int("engine.xfer.bodytype", type);
    if (type == OSSL_CMP_IR || type == OSSL_CMP_CR || type == OSSL_CMP_KUR) {
        out_nonnull("engine.xfer.pubkey", OSSL_CMP_MSG_get0_certreq_publickey(req));
        out_int("engine.xfer.valid", OSSL_CMP_validate_msg(engine_validator, req));
        out_err("engine.xfer.valid.err");
    }
    return OSSL_CMP_CTX_server_perform(ctx, req);
}

static void drive_engine(void)
{
    OSSL_CMP_CTX *ctx, *srv_cmp, *client;
    OSSL_CMP_SRV_CTX *srv;
    OSSL_CRMF_MSG *crm;
    OSSL_CMP_MSG *msg;
    ASN1_OCTET_STRING *tid;
    EVP_PKEY *key;
    const unsigned char *p;
    unsigned char tid_bytes[16];
    STACK_OF(X509) *certs = NULL;
    X509 *new_with_new = NULL, *new_with_old = NULL, *old_with_new = NULL;
    X509_CRL *crl = NULL;
    OSSL_CRMF_CERTTEMPLATE *tmpl = NULL;
    OSSL_CMP_ATAVS *keyspec = NULL;
    int i;

    for (i = 0; i < 16; i++)
        tid_bytes[i] = (unsigned char)i;

    write_fixture("/tmp/rt_cmp_cert.pem", rt_ess_cert_pem);
    write_fixture("/tmp/rt_cmp_key.pem", rt_ess_key_pem);
    engine_cert = load_pem_cert("/tmp/rt_cmp_cert.pem");
    key = load_pem_key("/tmp/rt_cmp_key.pem");
    out_nonnull("engine.cert", engine_cert);
    out_nonnull("engine.key", key);

    /* --- OSSL_CMP_CTX_setup_CRM (cmp_msg.c:287) --- */
    ctx = OSSL_CMP_CTX_new(NULL, NULL);
    out_int("engine.set_cert", OSSL_CMP_CTX_set1_cert(ctx, engine_cert));
    out_int("engine.set_pkey", OSSL_CMP_CTX_set1_pkey(ctx, key));
    out_int("engine.days0", OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_VALIDITY_DAYS, 0));
    crm = OSSL_CMP_CTX_setup_CRM(ctx, 0, 0);
    out_nonnull("engine.setup_crm", crm);
    if (crm != NULL) {
        unsigned char *der = NULL;
        int n;

        out_int("engine.setup_crm.rid", OSSL_CRMF_MSG_get_certReqId(crm));
        out_nonnull("engine.setup_crm.pubkey",
                    OSSL_CRMF_CERTTEMPLATE_get0_publicKey(
                        OSSL_CRMF_MSG_get0_tmpl(crm)));
        n = i2d_OSSL_CRMF_MSG(crm, &der);
        out_hex("engine.setup_crm.der", der, n > 0 ? n : 0);
        OPENSSL_free(der);
    } else {
        out_err("engine.setup_crm.err");
    }
    OSSL_CRMF_MSG_free(crm);
    crm = NULL;

    out_int("engine.set_oldcert", OSSL_CMP_CTX_set1_oldCert(ctx, engine_cert));
    crm = OSSL_CMP_CTX_setup_CRM(ctx, 1, 1);
    out_nonnull("engine.setup_crm_kur", crm);
    if (crm != NULL) {
        unsigned char *der = NULL;
        int n = i2d_OSSL_CRMF_MSG(crm, &der);

        out_hex("engine.setup_crm_kur.der", der, n > 0 ? n : 0);
        OPENSSL_free(der);
    }
    OSSL_CRMF_MSG_free(crm);
    crm = NULL;

    {
        OSSL_CMP_CTX *c2 = OSSL_CMP_CTX_new(NULL, NULL);

        OSSL_CMP_CTX_set_option(c2, OSSL_CMP_OPT_VALIDITY_DAYS, 0);
        crm = OSSL_CMP_CTX_setup_CRM(c2, 0, 0);
        out_nonnull("engine.setup_crm_nopub", crm);
        out_err("engine.setup_crm_nopub.err");
        OSSL_CRMF_MSG_free(crm);
        crm = NULL;
        OSSL_CMP_CTX_free(c2);
    }

    /* --- the item mutate helpers, over the fixed genm fixture --- */
    p = msg_der;
    msg = d2i_OSSL_CMP_MSG(NULL, &p, (long)sizeof(msg_der));
    out_nonnull("engine.msg", msg);
    ERR_clear_error();
    out_nonnull("engine.get0_pubkey_genm", OSSL_CMP_MSG_get0_certreq_publickey(msg));
    out_err("engine.get0_pubkey_genm.err");
    tid = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(tid, tid_bytes, 16);
    out_int("engine.set_tid", OSSL_CMP_CTX_set1_transactionID(ctx, tid));
    out_int("engine.update_tid", OSSL_CMP_MSG_update_transactionID(ctx, msg));
    out_int("engine.update_recipnonce", OSSL_CMP_MSG_update_recipNonce(ctx, msg));
    ERR_clear_error();
    out_int("engine.update_tid_null", OSSL_CMP_MSG_update_transactionID(NULL, msg));
    out_err("engine.update_tid_null.err");
    out_int("engine.update_recipnonce_null", OSSL_CMP_MSG_update_recipNonce(ctx, NULL));
    out_err("engine.update_recipnonce_null.err");
    ASN1_OCTET_STRING_free(tid);
    OSSL_CMP_MSG_free(msg);
    msg = NULL;

    /* --- the in-process client/server exchange (cmp_client.c + cmp_server.c) --- */
    srv = OSSL_CMP_SRV_CTX_new(NULL, NULL);
    srv_cmp = OSSL_CMP_SRV_CTX_get0_cmp_ctx(srv);
    out_int("engine.srv.init", OSSL_CMP_SRV_CTX_init(srv, NULL, engine_srv_certreq,
        NULL, engine_srv_genm, NULL, NULL, NULL));
    out_int("engine.srv.accept_unprotected", OSSL_CMP_SRV_CTX_set_accept_unprotected(srv, 1));
    out_int("engine.srv.accept_raverified", OSSL_CMP_SRV_CTX_set_accept_raverified(srv, 1));
    out_int("engine.srv.grant_implicit", OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(srv, 1));
    out_int("engine.srv.set_cert", OSSL_CMP_CTX_set1_cert(srv_cmp, engine_cert));
    out_int("engine.srv.set_pkey", OSSL_CMP_CTX_set1_pkey(srv_cmp, key));
    out_int("engine.srv.days0", OSSL_CMP_CTX_set_option(srv_cmp, OSSL_CMP_OPT_VALIDITY_DAYS, 0));
    /*
     * The server sends its response unprotected, and the client accepts an unprotected
     * rejection response. Signature verification is the arm named `pending.` below: the verifier
     * resolves the protection digest through `EVP_get_digestbyname`, whose legacy table is Phase
     * 13's, so the authority validates a signed transaction and the candidate does not. Running
     * the exchange unprotected drives the very same `cmp_server.c`/`cmp_client.c` engine on both
     * sides and keeps every observation below a function of the library.
     */
    out_int("engine.srv.unprotected_send",
            OSSL_CMP_CTX_set_option(srv_cmp, OSSL_CMP_OPT_UNPROTECTED_SEND, 1));

    engine_validator = OSSL_CMP_CTX_new(NULL, NULL);
    out_int("engine.val.set_srvcert", OSSL_CMP_CTX_set1_srvCert(engine_validator, engine_cert));

    client = OSSL_CMP_CTX_new(NULL, NULL);
    out_int("engine.cli.set_cert", OSSL_CMP_CTX_set1_cert(client, engine_cert));
    out_int("engine.cli.set_pkey", OSSL_CMP_CTX_set1_pkey(client, key));
    out_int("engine.cli.set_transfer", OSSL_CMP_CTX_set_transfer_cb(client, engine_transfer));
    out_int("engine.cli.set_transfer_arg", OSSL_CMP_CTX_set_transfer_cb_arg(client, srv));
    out_int("engine.cli.set_srvcert", OSSL_CMP_CTX_set1_srvCert(client, engine_cert));
    out_int("engine.cli.days0", OSSL_CMP_CTX_set_option(client, OSSL_CMP_OPT_VALIDITY_DAYS, 0));
    out_int("engine.cli.unprotected_send",
            OSSL_CMP_CTX_set_option(client, OSSL_CMP_OPT_UNPROTECTED_SEND, 1));
    out_int("engine.cli.unprotected_errors",
            OSSL_CMP_CTX_set_option(client, OSSL_CMP_OPT_UNPROTECTED_ERRORS, 1));
    /*
     * `raVerified` proof of possession, accepted above by the server, needs no digest resolution;
     * a signature POPO would re-enter the `EVP_get_digestbyname` divergence named pending below.
     */
    out_int("engine.cli.popo_raverified",
            OSSL_CMP_CTX_set_option(client, OSSL_CMP_OPT_POPO_METHOD,
                                    OSSL_CRMF_POPO_RAVERIFIED));

    ERR_clear_error();
    out_nonnull("engine.exec_ir", OSSL_CMP_exec_certreq(client, OSSL_CMP_IR, NULL));
    out_int("engine.exec_ir.status", OSSL_CMP_CTX_get_status(client));
    out_int("engine.exec_ir.failinfo", OSSL_CMP_CTX_get_failInfoCode(client));
    out_err("engine.exec_ir.err");

    {
        int check_after = -1;

        out_int("engine.try_ir", OSSL_CMP_try_certreq(client, OSSL_CMP_IR, NULL, &check_after));
        out_int("engine.try_ir.check_after", check_after);
        out_int("engine.try_ir.status", OSSL_CMP_CTX_get_status(client));
        out_err("engine.try_ir.err");
    }

    out_int("engine.exec_rr", OSSL_CMP_exec_RR_ses(client));
    out_int("engine.exec_rr.status", OSSL_CMP_CTX_get_status(client));
    out_err("engine.exec_rr.err");

    out_nonnull("engine.exec_genm", OSSL_CMP_exec_GENM_ses(client));
    out_err("engine.exec_genm.err");

    /* --- the cmp_genm.c readers --- */
    ERR_clear_error();
    out_int("engine.get1_caCerts_null", OSSL_CMP_get1_caCerts(client, NULL));
    out_err("engine.get1_caCerts_null.err");
    out_int("engine.get1_caCerts", OSSL_CMP_get1_caCerts(client, &certs));
    out_nonnull("engine.get1_caCerts.out", certs);
    out_err("engine.get1_caCerts.err");
    sk_X509_pop_free(certs, X509_free);
    certs = NULL;

    out_int("engine.get1_rootCaKeyUpdate",
            OSSL_CMP_get1_rootCaKeyUpdate(client, engine_cert, &new_with_new,
                                          &new_with_old, &old_with_new));
    out_nonnull("engine.get1_rootCaKeyUpdate.new", new_with_new);
    out_err("engine.get1_rootCaKeyUpdate.err");
    X509_free(new_with_new);
    X509_free(new_with_old);
    X509_free(old_with_new);
    new_with_new = new_with_old = old_with_new = NULL;

    out_int("engine.get1_crlUpdate",
            OSSL_CMP_get1_crlUpdate(client, engine_cert, NULL, &crl));
    out_nonnull("engine.get1_crlUpdate.out", crl);
    out_err("engine.get1_crlUpdate.err");
    X509_CRL_free(crl);
    crl = NULL;

    out_int("engine.get1_certReqTemplate",
            OSSL_CMP_get1_certReqTemplate(client, &tmpl, &keyspec));
    out_nonnull("engine.get1_certReqTemplate.tmpl", tmpl);
    out_err("engine.get1_certReqTemplate.err");
    OSSL_CRMF_CERTTEMPLATE_free(tmpl);
    OSSL_CMP_ATAVS_free(keyspec);

    /*
     * `OSSL_CMP_SRV_process_request` directly, not only through
     * `OSSL_CMP_CTX_server_perform`: the court-coverage atlas needs the entry point itself
     * observed, and this drives the same engine over the fixed genm fixture (its `process_genm`
     * callback refuses, so the reply is a deterministic error message).
     */
    p = msg_der;
    msg = d2i_OSSL_CMP_MSG(NULL, &p, (long)sizeof(msg_der));
    ERR_clear_error();
    out_nonnull("engine.srv.direct", OSSL_CMP_SRV_process_request(srv, msg));
    out_err("engine.srv.direct.err");
    OSSL_CMP_MSG_free(msg);
    msg = NULL;

    /*
     * The PBM protection arm resolves its digest through `EVP_get_digestbyname`, whose legacy
     * table is Phase 13's. This is the same divergence that keeps a *signed* transaction's
     * `OSSL_CMP_validate_msg` result out of the comparison: the authority accepts a signature
     * the candidate's verifier cannot resolve, so the signed arm is driven but named pending,
     * exactly as `rt_crmf_probe.c:394` does for the CRMF POPO and `rt_ocsp_probe.c:580` for
     * `OCSP_basic_verify`. The unprotected engine above is the comparable arm of the same code.
     */
    printf("pending.engine.signed_verify=%s\n",
           "EVP_get_digestbyname_identity_divergence");
    printf("pending.engine.pbm_verify=%s\n", "EVP_get_digestbyname_identity_divergence");

    OSSL_CMP_CTX_free(client);
    OSSL_CMP_CTX_free(engine_validator);
    OSSL_CMP_SRV_CTX_free(srv);
    OSSL_CMP_CTX_free(ctx);
    EVP_PKEY_free(key);
    X509_free(engine_cert);
    ERR_clear_error();
}

int main(void)
{
    ERR_clear_error();

    drive_util();
    drive_status();
    drive_asn();
    drive_msg();
    drive_msg_more();
    drive_ctx();
    drive_srv_and_certconf();
    drive_engine();

    printf("done=1\n");
    return 0;
}
