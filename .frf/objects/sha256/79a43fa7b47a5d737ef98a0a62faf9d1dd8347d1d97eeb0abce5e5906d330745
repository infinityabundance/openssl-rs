/*
 * RT-X509-V3 -- the Phase 11.5 `v3` function and configuration layer, driven.
 *
 * This is the behavioural court `docs/PHASE-11-SUBPHASES.md` section 2 row 11.5 names, and it is
 * what turns the RFC 3779 address/AS-identifier exports and the two remaining configuration
 * helpers from the reference basis's `referenced` into `called` (forensics/atlas/court-coverage.json).
 * Like every court here it is one C program compiled once against the admitted authority and once
 * against the candidate distribution shell, whose two transcripts are diffed line by line. Every
 * observation is an integer, a byte-for-byte equality, a `nonnull`/`null`, the hex of a short
 * buffer, or an error coordinate (`lib.reason`) -- **never a pointer address**, and the IP/AS
 * values the printers emit are compared as the hex of the printer's own output rather than as
 * printed text, so the transcript is a function of the library and not of the probe's frame
 * (`probe_hygiene.py` compiles it at -O0/-O1/-O2 and requires that).
 *
 * What it drives, and how
 * -----------------------
 * Value builders, not hand-built DER: `X509v3_addr_add_prefix`/`_add_range`/`_add_inherit` and
 * `X509v3_asid_add_id_or_range`/`_add_inherit` construct an `IPAddrBlocks` (a
 * `STACK_OF(IPAddressFamily)` the probe creates with `sk_IPAddressFamily_new_null()`) and an
 * `ASIdentifiers`, and every arm below drives a builder's value, which is what those builders are
 * for. Over them the probe exercises:
 *
 *   * `crypto/x509/v3_addr.c` -- `X509v3_addr_get_afi`, `_get_range` (both a prefix and a range
 *     element, plus the short-buffer and unknown-AFI refusals), `_inherits`, `_is_canonical` and
 *     `_canonize` (a two-family value that is already canonical, and a two-adjacent-`/25` value
 *     that is not and merges to one `/24`), `_subset` (a `/24` in a `/23`, its converse, the
 *     same-object, and the NULL arms); the four item groups `IPAddressFamily`,
 *     `IPAddressChoice`, `IPAddressOrRange`, `IPAddressRange` through their `_it`/`_new`/`_free`
 *     doors and an `i2d_` -> `d2i_` -> `i2d_` round-trip whose re-encoded bytes must equal the
 *     first encoding. The `IPAddressChoice`/`IPAddressFamily` round-trips are done for both the
 *     `addressesOrRanges` and the `inherit` arm.
 *
 *   * `crypto/x509/v3_asid.c` -- `X509v3_asid_inherits`, `_is_canonical` and `_canonize` (a
 *     mis-ordered id/range value, a two-adjacent-id value that merges to one range, an
 *     inheriting value, an empty list and a duplicate-id overlap that raise), `_subset` (an id
 *     contained in a range, its converse, same-object and the NULL arms); the four item groups
 *     `ASIdentifiers`, `ASIdentifierChoice`, `ASIdOrRange`, `ASRange` through their
 *     `_it`/`_new`/`_free` doors and the same `i2d_`/`d2i_` round-trip (the `ASIdOrRange`
 *     round-trip for both the `id` and the `range` arm).
 *
 *   * `crypto/x509/v3_conf.c` -- `X509V3_EXT_i2d` over an `IPAddrBlocks` and an `ASIdentifiers`,
 *     critical and not, printing each resulting extension's identity and full DER, plus the
 *     unknown-NID refusal. `X509V3_EXT_print` is then run **over those extension objects**, so
 *     the method tables the two units land (`ossl_v3_addr`, whose `i2r` is `i2r_IPAddrBlocks`, and
 *     `ossl_v3_asid`, whose `i2r` is `i2r_ASIdentifiers`) actually decode the extension's DER and
 *     reach their RFC 3779 printer. The printed bytes are compared as hex; no address is ever
 *     printed as text.
 *
 *   * `crypto/x509/v3_utl.c` -- `X509V3_add_value_int` over a real `ASN1_INTEGER` into a
 *     `STACK_OF(CONF_VALUE)`, and its NULL-`aint` early answer.
 *
 * The refusals each carry their error coordinate: a NULL argument to `X509v3_addr_canonize`
 * (raising `X509V3_R_INVALID_NULL_ARGUMENT`), an out-of-range prefix length and an inverted range
 * to the address builders (which raise nothing), an unknown NID to `X509V3_EXT_i2d`
 * (`X509V3_R_UNKNOWN_EXTENSION`), and the duplicate-id and empty-list `X509v3_asid_canonize`
 * refusals (`X509V3_R_EXTENSION_VALUE_ERROR`). The error queue is popped at the start of every
 * arm that expects to raise and read after it.
 *
 * What it deliberately does not do
 * --------------------------------
 * It prints no pointer address and no wall clock, and it does not run the RFC 3779 path-validation
 * entries (`X509v3_{asid,addr}_validate_path` / `..._validate_resource_set`): those need an
 * `X509_STORE_CTX` chain and are driven by `RT-X509-VERIFY-SURFACE`. Nothing here is a parity
 * claim about a certificate's meaning; it compares the bytes and control flow these two units
 * produce.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* ---------------------------------------------------------------------------------------------
 * Output helpers -- every line is `key=value`. No pointer or IP address is ever printed as text.
 * --------------------------------------------------------------------------------------------- */

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_ptr(const char *key, const void *p)
{
    printf("%s=%s\n", key, p != NULL ? "nonnull" : "null");
}

/* The first error on the queue as `lib.reason`, then the queue is cleared. */
static void out_err(const char *key)
{
    unsigned long e = ERR_get_error();

    if (e == 0) {
        printf("%s=none\n", key);
        return;
    }
    printf("%s=%d.%d\n", key, ERR_GET_LIB(e), ERR_GET_REASON(e));
    ERR_clear_error();
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

/* The bytes a memory BIO holds; the BIO is rewound for the next arm. */
static void emit_mem(const char *key, BIO *b)
{
    char *data = NULL;
    long n = BIO_get_mem_data(b, &data);

    out_hex(key, (const unsigned char *)data, n);
    BIO_reset(b);
}

/* An extension's identity and full DER, so `X509V3_EXT_i2d`'s result is compared byte for byte. */
static void out_ext(const char *key, X509_EXTENSION *e)
{
    unsigned char *der = NULL;
    int len, i;

    if (e == NULL) {
        printf("%s=null\n", key);
        return;
    }
    printf("%s.nid=%d\n", key, OBJ_obj2nid(X509_EXTENSION_get_object(e)));
    printf("%s.critical=%d\n", key, X509_EXTENSION_get_critical(e));
    printf("%s.data.len=%d\n", key, ASN1_STRING_length(X509_EXTENSION_get_data(e)));
    len = i2d_X509_EXTENSION(e, &der);
    printf("%s.der.len=%d\n", key, len);
    printf("%s.der.hex=", key);
    for (i = 0; i < len; i++)
        printf("%02x", der[i]);
    printf("\n");
    OPENSSL_free(der);
}

/* ---------------------------------------------------------------------------------------------
 * The item round-trip. Every item group's `_new`/`_free`/`_it` and `d2i_`/`i2d_` share one ABI
 * shape (`i2d` writes bytes, `d2i` reads them, `free` disposes), so one driver covers all eight
 * item types; the value each arm passes is a live one the builders above produced, not a
 * hand-allocated struct.
 * --------------------------------------------------------------------------------------------- */

typedef int (*probe_i2d)(const void *a, unsigned char **out);
typedef void *(*probe_d2i)(void **a, const unsigned char **in, long len);
typedef void (*probe_free)(void *a);

static void rt_item(const char *key, void *v, probe_i2d enc, probe_d2i dec, probe_free fr)
{
    unsigned char *der = NULL, *der2 = NULL;
    const unsigned char *p;
    int len = -1, len2 = -1;
    void *w = NULL;
    char k[96];

    if (v != NULL)
        len = enc(v, &der);
    snprintf(k, sizeof k, "%s.enc.len", key);
    out_int(k, len);
    snprintf(k, sizeof k, "%s.der", key);
    out_hex(k, der, len > 0 ? len : 0);
    if (v != NULL && len >= 0) {
        p = der;
        w = dec(NULL, &p, len);
    }
    snprintf(k, sizeof k, "%s.dec", key);
    out_ptr(k, w);
    if (w != NULL)
        len2 = enc(w, &der2);
    snprintf(k, sizeof k, "%s.roundtrip", key);
    out_int(k, len2 == len && (len <= 0 || memcmp(der, der2, (size_t)len) == 0));
    OPENSSL_free(der2);
    if (w != NULL)
        fr(w);
    OPENSSL_free(der);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.5 -- `crypto/x509/v3_addr.c`'s builders and value accessors.
 *
 * `addr_blocks_fixture()` builds an `IPAddrBlocks` with two families: IPv4 carrying a `/24`
 * prefix and a non-prefix range, IPv6 carrying a `/32` prefix. The families are pushed IPv4 then
 * IPv6, so the value is already canonical and `X509v3_addr_canonize` must accept it. Reading the
 * value back needs the public struct layout (`x509v3.h` defines `IPAddressFamily_st` and the two
 * unions), which the header supplies.
 * --------------------------------------------------------------------------------------------- */

static IPAddrBlocks *addr_blocks_fixture(void)
{
    static unsigned char v4_24[4] = { 192, 0, 2, 0 };
    static unsigned char v4_rmin[4] = { 198, 51, 100, 1 };
    static unsigned char v4_rmax[4] = { 198, 51, 100, 5 };
    static unsigned char v6_32[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0 };
    IPAddrBlocks *addr = sk_IPAddressFamily_new_null();

    out_ptr("addr.blocks", addr);
    out_int("addr.add_prefix.v4",
            X509v3_addr_add_prefix(addr, IANA_AFI_IPV4, NULL, v4_24, 24));
    out_int("addr.add_range.v4",
            X509v3_addr_add_range(addr, IANA_AFI_IPV4, NULL, v4_rmin, v4_rmax));
    out_int("addr.add_prefix.v6",
            X509v3_addr_add_prefix(addr, IANA_AFI_IPV6, NULL, v6_32, 32));
    out_int("addr.family.count", sk_IPAddressFamily_num(addr));
    return addr;
}

static void drive_addr_values(IPAddrBlocks *addr)
{
    static unsigned char mn[16], mx[16];
    IPAddressFamily *f0 = sk_IPAddressFamily_value(addr, 0);
    IPAddressFamily *f1 = sk_IPAddressFamily_value(addr, 1);
    IPAddressChoice *ch = f0->ipAddressChoice;
    IPAddressOrRanges *aors = ch->u.addressesOrRanges;
    IPAddressOrRange *aor0 = sk_IPAddressOrRange_value(aors, 0);
    IPAddressOrRange *aor1 = sk_IPAddressOrRange_value(aors, 1);

    out_int("addr.get_afi.v4", X509v3_addr_get_afi(f0));
    out_int("addr.get_afi.v6", X509v3_addr_get_afi(f1));
    out_int("addr.get_afi.null", X509v3_addr_get_afi(NULL));
    out_int("addr.inherits", X509v3_addr_inherits(addr));
    out_int("addr.choice.type", ch->type);
    out_int("addr.aors.count", sk_IPAddressOrRange_num(aors));
    out_int("addr.aor0.type", aor0->type);
    out_int("addr.aor1.type", aor1->type);

    ERR_clear_error();
    out_int("addr.is_canonical", X509v3_addr_is_canonical(addr));
    out_err("addr.is_canonical.err");
    out_int("addr.canonize", X509v3_addr_canonize(addr));
    out_int("addr.is_canonical.after", X509v3_addr_is_canonical(addr));

    /* get_range: the prefix element and the range element, each four raw bytes. */
    memset(mn, 0, sizeof mn);
    memset(mx, 0, sizeof mx);
    out_int("addr.get_range.prefix",
            X509v3_addr_get_range(aor0, IANA_AFI_IPV4, mn, mx, 4));
    out_hex("addr.get_range.prefix.min", mn, 4);
    out_hex("addr.get_range.prefix.max", mx, 4);
    memset(mn, 0, sizeof mn);
    memset(mx, 0, sizeof mx);
    out_int("addr.get_range.range",
            X509v3_addr_get_range(aor1, IANA_AFI_IPV4, mn, mx, 4));
    out_hex("addr.get_range.range.min", mn, 4);
    out_hex("addr.get_range.range.max", mx, 4);

    /* refusals: too-small a buffer, unknown AFI, NULL aor. */
    out_int("addr.get_range.short",
            X509v3_addr_get_range(aor0, IANA_AFI_IPV4, mn, mx, 3));
    out_int("addr.get_range.bad_afi",
            X509v3_addr_get_range(aor0, 99, mn, mx, 16));
    out_int("addr.get_range.null",
            X509v3_addr_get_range(NULL, IANA_AFI_IPV4, mn, mx, 4));
    out_int("addr.get_range.null_buf",
            X509v3_addr_get_range(aor0, IANA_AFI_IPV4, NULL, mx, 4));
}

static void drive_addr_items(IPAddrBlocks *addr)
{
    IPAddressFamily *f0 = sk_IPAddressFamily_value(addr, 0);
    IPAddressChoice *ch = f0->ipAddressChoice;
    IPAddressOrRanges *aors = ch->u.addressesOrRanges;
    IPAddressOrRange *aor0 = sk_IPAddressOrRange_value(aors, 0);
    IPAddressOrRange *aor1 = sk_IPAddressOrRange_value(aors, 1);
    IPAddressRange *rg = aor1->u.addressRange;
    IPAddressFamily *nf;
    IPAddressChoice *nc;
    IPAddressOrRange *no;
    IPAddressRange *nr;

    out_ptr("addr.it.family", IPAddressFamily_it());
    out_ptr("addr.it.choice", IPAddressChoice_it());
    out_ptr("addr.it.orrange", IPAddressOrRange_it());
    out_ptr("addr.it.range", IPAddressRange_it());

    rt_item("addr.family", f0, (probe_i2d)i2d_IPAddressFamily,
            (probe_d2i)d2i_IPAddressFamily, (probe_free)IPAddressFamily_free);
    rt_item("addr.choice.list", ch, (probe_i2d)i2d_IPAddressChoice,
            (probe_d2i)d2i_IPAddressChoice, (probe_free)IPAddressChoice_free);
    rt_item("addr.orrange.prefix", aor0, (probe_i2d)i2d_IPAddressOrRange,
            (probe_d2i)d2i_IPAddressOrRange, (probe_free)IPAddressOrRange_free);
    rt_item("addr.orrange.range", aor1, (probe_i2d)i2d_IPAddressOrRange,
            (probe_d2i)d2i_IPAddressOrRange, (probe_free)IPAddressOrRange_free);
    rt_item("addr.range", rg, (probe_i2d)i2d_IPAddressRange,
            (probe_d2i)d2i_IPAddressRange, (probe_free)IPAddressRange_free);

    /* The `inherit` arm of the choice, reached through a family that inherits. */
    {
        IPAddrBlocks *inh = sk_IPAddressFamily_new_null();
        IPAddressFamily *fi = NULL;

        X509v3_addr_add_inherit(inh, IANA_AFI_IPV4, NULL);
        fi = sk_IPAddressFamily_value(inh, 0);
        out_int("addr.inherit.afi", X509v3_addr_get_afi(fi));
        out_int("addr.inherit.choice.type", fi->ipAddressChoice->type);
        rt_item("addr.choice.inherit", fi->ipAddressChoice,
                (probe_i2d)i2d_IPAddressChoice, (probe_d2i)d2i_IPAddressChoice,
                (probe_free)IPAddressChoice_free);
        rt_item("addr.family.inherit", fi, (probe_i2d)i2d_IPAddressFamily,
                (probe_d2i)d2i_IPAddressFamily, (probe_free)IPAddressFamily_free);
        sk_IPAddressFamily_pop_free(inh, IPAddressFamily_free);
    }

    nf = IPAddressFamily_new();
    nc = IPAddressChoice_new();
    no = IPAddressOrRange_new();
    nr = IPAddressRange_new();
    out_ptr("addr.family.new", nf);
    out_ptr("addr.choice.new", nc);
    out_ptr("addr.orrange.new", no);
    out_ptr("addr.range.new", nr);
    IPAddressFamily_free(nf);
    IPAddressChoice_free(nc);
    IPAddressOrRange_free(no);
    IPAddressRange_free(nr);
    IPAddressFamily_free(NULL);
    IPAddressChoice_free(NULL);
    IPAddressOrRange_free(NULL);
    IPAddressRange_free(NULL);
    out_int("addr.items.free", 1);
}

static void drive_addr_safi(void)
{
    static unsigned char v4_24[4] = { 203, 0, 113, 0 };
    static unsigned char v4_25[4] = { 203, 0, 113, 0 };
    unsigned safi = 1;
    IPAddrBlocks *sf = sk_IPAddressFamily_new_null();
    IPAddressFamily *f;

    out_int("addr.add_prefix.safi",
            X509v3_addr_add_prefix(sf, IANA_AFI_IPV4, &safi, v4_24, 24));
    f = sk_IPAddressFamily_value(sf, 0);
    out_int("addr.safi.family_len", f->addressFamily->length);
    out_int("addr.safi.get_afi", X509v3_addr_get_afi(f));
    out_int("addr.add_prefix.safi.again",
            X509v3_addr_add_prefix(sf, IANA_AFI_IPV4, &safi, v4_25, 25));
    out_int("addr.safi.family_count", sk_IPAddressFamily_num(sf));
    sk_IPAddressFamily_pop_free(sf, IPAddressFamily_free);
}

static void drive_addr_canonize_split(void)
{
    static unsigned char v4_25a[4] = { 192, 0, 2, 0 };
    static unsigned char v4_25b[4] = { 192, 0, 2, 128 };
    static unsigned char mn[4], mx[4];
    IPAddrBlocks *c = sk_IPAddressFamily_new_null();
    IPAddressFamily *f;
    IPAddressOrRanges *aors;
    IPAddressOrRange *aor;

    X509v3_addr_add_prefix(c, IANA_AFI_IPV4, NULL, v4_25a, 25);
    X509v3_addr_add_prefix(c, IANA_AFI_IPV4, NULL, v4_25b, 25);
    out_int("addr.split.before", X509v3_addr_is_canonical(c));
    out_int("addr.split.canonize", X509v3_addr_canonize(c));
    out_int("addr.split.after", X509v3_addr_is_canonical(c));

    f = sk_IPAddressFamily_value(c, 0);
    aors = f->ipAddressChoice->u.addressesOrRanges;
    out_int("addr.split.count", sk_IPAddressOrRange_num(aors));
    aor = sk_IPAddressOrRange_value(aors, 0);
    out_int("addr.split.type", aor->type);
    memset(mn, 0, sizeof mn);
    memset(mx, 0, sizeof mx);
    out_int("addr.split.get_range",
            X509v3_addr_get_range(aor, IANA_AFI_IPV4, mn, mx, 4));
    out_hex("addr.split.min", mn, 4);
    out_hex("addr.split.max", mx, 4);
    sk_IPAddressFamily_pop_free(c, IPAddressFamily_free);
}

static void drive_addr_subset(void)
{
    static unsigned char v4_24[4] = { 198, 51, 100, 0 };
    static unsigned char v4_23[4] = { 198, 51, 100, 0 };
    IPAddrBlocks *a = sk_IPAddressFamily_new_null();
    IPAddrBlocks *b = sk_IPAddressFamily_new_null();
    IPAddrBlocks *inh = sk_IPAddressFamily_new_null();

    X509v3_addr_add_prefix(a, IANA_AFI_IPV4, NULL, v4_24, 24);
    X509v3_addr_add_prefix(b, IANA_AFI_IPV4, NULL, v4_23, 23);
    X509v3_addr_add_inherit(inh, IANA_AFI_IPV4, NULL);

    out_int("addr.subset.a_b", X509v3_addr_subset(a, b));
    out_int("addr.subset.b_a", X509v3_addr_subset(b, a));
    out_int("addr.subset.a_a", X509v3_addr_subset(a, a));
    out_int("addr.subset.null_b", X509v3_addr_subset(a, NULL));
    out_int("addr.subset.null_a", X509v3_addr_subset(NULL, b));
    out_int("addr.subset.inherit", X509v3_addr_subset(inh, b));

    sk_IPAddressFamily_pop_free(a, IPAddressFamily_free);
    sk_IPAddressFamily_pop_free(b, IPAddressFamily_free);
    sk_IPAddressFamily_pop_free(inh, IPAddressFamily_free);
}

static void drive_addr_refusals(void)
{
    static unsigned char v4_24[4] = { 192, 0, 2, 0 };
    static unsigned char v4_big[4] = { 192, 0, 2, 5 };
    static unsigned char v4_small[4] = { 192, 0, 2, 1 };
    IPAddrBlocks *e = sk_IPAddressFamily_new_null();

    ERR_clear_error();
    out_int("addr.canonize.null", X509v3_addr_canonize(NULL));
    out_err("addr.canonize.null.err");
    out_int("addr.is_canonical.null", X509v3_addr_is_canonical(NULL));
    out_int("addr.inherits.null", X509v3_addr_inherits(NULL));
    out_int("addr.subset.null_null", X509v3_addr_subset(NULL, NULL));

    /* An out-of-range prefix length: `make_addressPrefix` refuses, raising nothing. */
    ERR_clear_error();
    out_int("addr.add_prefix.bad_len",
            X509v3_addr_add_prefix(e, IANA_AFI_IPV4, NULL, v4_24, 33));
    out_err("addr.add_prefix.bad_len.err");
    /* An unknown AFI has zero length, so any positive prefix length is out of range. */
    out_int("addr.add_prefix.bad_afi",
            X509v3_addr_add_prefix(e, 99, NULL, v4_24, 8));
    /* An inverted range (min > max): `make_addressRange` refuses. */
    out_int("addr.add_range.inverted",
            X509v3_addr_add_range(e, IANA_AFI_IPV4, NULL, v4_big, v4_small));
    /* A NULL container reaches the push refusal. */
    out_int("addr.add_prefix.null_addr",
            X509v3_addr_add_prefix(NULL, IANA_AFI_IPV4, NULL, v4_24, 24));
    out_int("addr.add_inherit.null", X509v3_addr_add_inherit(NULL, IANA_AFI_IPV4, NULL));

    sk_IPAddressFamily_pop_free(e, IPAddressFamily_free);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.5 -- `crypto/x509/v3_asid.c`'s builders and value accessors.
 *
 * `asid_fixture()` adds an AS number and an AS range to `asnum` and one AS number to `rdi`; the
 * two `asnum` elements are mis-ordered on insert, so `X509v3_asid_canonize` has to sort them. The
 * adjacent-id and duplicate-id arms build their own values.
 * --------------------------------------------------------------------------------------------- */

static ASN1_INTEGER *mk_int(long v)
{
    ASN1_INTEGER *a = ASN1_INTEGER_new();

    if (a != NULL)
        ASN1_INTEGER_set(a, v);
    return a;
}

static ASIdentifiers *asid_fixture(void)
{
    ASIdentifiers *asid = ASIdentifiers_new();

    out_ptr("asid.ids", asid);
    out_int("asid.add_id",
            X509v3_asid_add_id_or_range(asid, V3_ASID_ASNUM, mk_int(64512), NULL));
    out_int("asid.add_range",
            X509v3_asid_add_id_or_range(asid, V3_ASID_ASNUM, mk_int(100), mk_int(200)));
    out_int("asid.add_rdi",
            X509v3_asid_add_id_or_range(asid, V3_ASID_RDI, mk_int(64496), NULL));
    out_int("asid.inherits", X509v3_asid_inherits(asid));
    out_int("asid.is_canonical", X509v3_asid_is_canonical(asid));
    out_int("asid.canonize", X509v3_asid_canonize(asid));
    out_int("asid.is_canonical.after", X509v3_asid_is_canonical(asid));
    return asid;
}

static void drive_asid_values(ASIdentifiers *asid)
{
    ASIdentifierChoice *c = asid->asnum;

    out_int("asid.asnum.type", c->type);
    out_int("asid.asnum.count", sk_ASIdOrRange_num(c->u.asIdsOrRanges));
    out_int("asid.asnum.0.type",
            sk_ASIdOrRange_value(c->u.asIdsOrRanges, 0)->type);
    out_int("asid.asnum.1.type",
            sk_ASIdOrRange_value(c->u.asIdsOrRanges, 1)->type);
    out_int("asid.asnum.0.min",
            ASN1_INTEGER_get(sk_ASIdOrRange_value(c->u.asIdsOrRanges, 0)->u.range->min));
    out_int("asid.asnum.0.max",
            ASN1_INTEGER_get(sk_ASIdOrRange_value(c->u.asIdsOrRanges, 0)->u.range->max));
    out_int("asid.asnum.1.id",
            ASN1_INTEGER_get(sk_ASIdOrRange_value(c->u.asIdsOrRanges, 1)->u.id));
    out_int("asid.rdi.type", asid->rdi->type);
    out_int("asid.rdi.id",
            ASN1_INTEGER_get(sk_ASIdOrRange_value(asid->rdi->u.asIdsOrRanges, 0)->u.id));
    out_int("asid.inherits.value", X509v3_asid_inherits(asid));
}

static void drive_asid_items(ASIdentifiers *asid)
{
    ASIdentifierChoice *c = asid->asnum;
    ASIdOrRange *r0 = sk_ASIdOrRange_value(c->u.asIdsOrRanges, 0);
    ASIdOrRange *r1 = sk_ASIdOrRange_value(c->u.asIdsOrRanges, 1);
    ASRange *rg = r0->u.range;
    ASIdentifiers *na;
    ASIdentifierChoice *nc;
    ASIdOrRange *nr;
    ASRange *nrg;

    out_ptr("asid.it.ids", ASIdentifiers_it());
    out_ptr("asid.it.choice", ASIdentifierChoice_it());
    out_ptr("asid.it.idorrange", ASIdOrRange_it());
    out_ptr("asid.it.range", ASRange_it());

    rt_item("asid.ids", asid, (probe_i2d)i2d_ASIdentifiers,
            (probe_d2i)d2i_ASIdentifiers, (probe_free)ASIdentifiers_free);
    rt_item("asid.choice", c, (probe_i2d)i2d_ASIdentifierChoice,
            (probe_d2i)d2i_ASIdentifierChoice, (probe_free)ASIdentifierChoice_free);
    rt_item("asid.idorrange.range", r0, (probe_i2d)i2d_ASIdOrRange,
            (probe_d2i)d2i_ASIdOrRange, (probe_free)ASIdOrRange_free);
    rt_item("asid.idorrange.id", r1, (probe_i2d)i2d_ASIdOrRange,
            (probe_d2i)d2i_ASIdOrRange, (probe_free)ASIdOrRange_free);
    rt_item("asid.range", rg, (probe_i2d)i2d_ASRange,
            (probe_d2i)d2i_ASRange, (probe_free)ASRange_free);

    /* The `inherit` arm of an `ASIdentifierChoice`. */
    {
        ASIdentifiers *inh = ASIdentifiers_new();

        X509v3_asid_add_inherit(inh, V3_ASID_ASNUM);
        out_int("asid.inherit.type", inh->asnum->type);
        rt_item("asid.choice.inherit", inh->asnum,
                (probe_i2d)i2d_ASIdentifierChoice, (probe_d2i)d2i_ASIdentifierChoice,
                (probe_free)ASIdentifierChoice_free);
        ASIdentifiers_free(inh);
    }

    na = ASIdentifiers_new();
    nc = ASIdentifierChoice_new();
    nr = ASIdOrRange_new();
    nrg = ASRange_new();
    out_ptr("asid.ids.new", na);
    out_ptr("asid.choice.new", nc);
    out_ptr("asid.idorrange.new", nr);
    out_ptr("asid.range.new", nrg);
    ASIdentifiers_free(na);
    ASIdentifierChoice_free(nc);
    ASIdOrRange_free(nr);
    ASRange_free(nrg);
    ASIdentifiers_free(NULL);
    ASIdentifierChoice_free(NULL);
    ASIdOrRange_free(NULL);
    ASRange_free(NULL);
    out_int("asid.items.free", 1);
}

static void drive_asid_inherit(void)
{
    ASIdentifiers *a = ASIdentifiers_new();
    ASN1_INTEGER *id;

    out_int("asid.add_inherit", X509v3_asid_add_inherit(a, V3_ASID_ASNUM));
    out_int("asid.add_inherit.again", X509v3_asid_add_inherit(a, V3_ASID_ASNUM));
    out_int("asid.add_inherit.rdi", X509v3_asid_add_inherit(a, V3_ASID_RDI));
    out_int("asid.inherit.inherits", X509v3_asid_inherits(a));
    out_int("asid.inherit.is_canonical", X509v3_asid_is_canonical(a));
    out_int("asid.inherit.canonize", X509v3_asid_canonize(a));

    /* An id cannot be added to a choice that already inherits. */
    id = mk_int(5);
    out_int("asid.add_id.after_inherit",
            X509v3_asid_add_id_or_range(a, V3_ASID_ASNUM, id, NULL));
    ASN1_INTEGER_free(id);

    out_int("asid.add_inherit.null", X509v3_asid_add_inherit(NULL, V3_ASID_ASNUM));
    out_int("asid.add_inherit.bad_which", X509v3_asid_add_inherit(a, 9));
    out_int("asid.add_id.null", X509v3_asid_add_id_or_range(NULL, V3_ASID_ASNUM, NULL, NULL));
    out_int("asid.add_id.bad_which",
            X509v3_asid_add_id_or_range(a, 9, NULL, NULL));
    ASIdentifiers_free(a);
}

static void drive_asid_canonize_adjacent(void)
{
    ASIdentifiers *a = ASIdentifiers_new();
    ASIdentifierChoice *c;
    ASIdOrRange *r;

    X509v3_asid_add_id_or_range(a, V3_ASID_ASNUM, mk_int(10), NULL);
    X509v3_asid_add_id_or_range(a, V3_ASID_ASNUM, mk_int(11), NULL);
    out_int("asid.adj.before", X509v3_asid_is_canonical(a));
    out_int("asid.adj.canonize", X509v3_asid_canonize(a));
    out_int("asid.adj.after", X509v3_asid_is_canonical(a));
    c = a->asnum;
    out_int("asid.adj.count", sk_ASIdOrRange_num(c->u.asIdsOrRanges));
    r = sk_ASIdOrRange_value(c->u.asIdsOrRanges, 0);
    out_int("asid.adj.type", r->type);
    out_int("asid.adj.min", ASN1_INTEGER_get(r->u.range->min));
    out_int("asid.adj.max", ASN1_INTEGER_get(r->u.range->max));
    ASIdentifiers_free(a);
}

static void drive_asid_refusals(void)
{
    ASIdentifiers *dup = ASIdentifiers_new();
    ASIdentifiers *empty = ASIdentifiers_new();

    /* Duplicate ids: canonical form forbids the overlap and canonize must refuse. */
    X509v3_asid_add_id_or_range(dup, V3_ASID_ASNUM, mk_int(10), NULL);
    X509v3_asid_add_id_or_range(dup, V3_ASID_ASNUM, mk_int(10), NULL);
    out_int("asid.dup.before", X509v3_asid_is_canonical(dup));
    ERR_clear_error();
    out_int("asid.dup.canonize", X509v3_asid_canonize(dup));
    out_err("asid.dup.canonize.err");

    /* An empty list is broken: neither canonical nor canonizable. */
    empty->asnum = ASIdentifierChoice_new();
    empty->asnum->type = ASIdentifierChoice_asIdsOrRanges;
    empty->asnum->u.asIdsOrRanges = sk_ASIdOrRange_new_null();
    out_int("asid.empty.is_canonical", X509v3_asid_is_canonical(empty));
    ERR_clear_error();
    out_int("asid.empty.canonize", X509v3_asid_canonize(empty));
    out_err("asid.empty.canonize.err");

    out_int("asid.is_canonical.null", X509v3_asid_is_canonical(NULL));
    out_int("asid.canonize.null", X509v3_asid_canonize(NULL));
    out_int("asid.inherits.null", X509v3_asid_inherits(NULL));
    out_int("asid.subset.null_null", X509v3_asid_subset(NULL, NULL));

    ASIdentifiers_free(dup);
    ASIdentifiers_free(empty);
}

static void drive_asid_subset(void)
{
    ASIdentifiers *a = ASIdentifiers_new();
    ASIdentifiers *b = ASIdentifiers_new();
    ASIdentifiers *inh = ASIdentifiers_new();

    X509v3_asid_add_id_or_range(a, V3_ASID_ASNUM, mk_int(100), NULL);
    X509v3_asid_add_id_or_range(b, V3_ASID_ASNUM, mk_int(100), mk_int(200));
    X509v3_asid_add_inherit(inh, V3_ASID_ASNUM);

    out_int("asid.subset.a_b", X509v3_asid_subset(a, b));
    out_int("asid.subset.b_a", X509v3_asid_subset(b, a));
    out_int("asid.subset.a_a", X509v3_asid_subset(a, a));
    out_int("asid.subset.null_b", X509v3_asid_subset(a, NULL));
    out_int("asid.subset.null_a", X509v3_asid_subset(NULL, b));
    out_int("asid.subset.inherit", X509v3_asid_subset(inh, b));

    ASIdentifiers_free(a);
    ASIdentifiers_free(b);
    ASIdentifiers_free(inh);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.5 -- `crypto/x509/v3_conf.c`'s `X509V3_EXT_i2d` and the RFC 3779 printers it reaches.
 *
 * `X509V3_EXT_i2d` encodes the internal value through the method's item and wraps it in a real
 * `X509_EXTENSION`. `X509V3_EXT_print` on that extension then decodes the DER through the same
 * item and calls the method's `i2r`, which is `i2r_IPAddrBlocks` / `i2r_ASIdentifiers`. The
 * printed bytes are compared as hex so the report carries no address text.
 * --------------------------------------------------------------------------------------------- */

static void drive_ext_i2d(IPAddrBlocks *addr, ASIdentifiers *asid)
{
    BIO *b = BIO_new(BIO_s_mem());
    X509_EXTENSION *ea, *ec, *es, *eu;

    ERR_clear_error();
    ea = X509V3_EXT_i2d(NID_sbgp_ipAddrBlock, 0, addr);
    out_ext("ext.addr", ea);
    out_err("ext.addr.err");
    out_int("ext.addr.print", X509V3_EXT_print(b, ea, 0, 0));
    emit_mem("ext.addr.print.out", b);
    out_int("ext.addr.print.indent", X509V3_EXT_print(b, ea, 0, 4));
    emit_mem("ext.addr.print.indent.out", b);

    ERR_clear_error();
    ec = X509V3_EXT_i2d(NID_sbgp_ipAddrBlock, 1, addr);
    out_ext("ext.addr.critical", ec);
    out_err("ext.addr.critical.err");

    ERR_clear_error();
    es = X509V3_EXT_i2d(NID_sbgp_autonomousSysNum, 0, asid);
    out_ext("ext.asid", es);
    out_err("ext.asid.err");
    out_int("ext.asid.print", X509V3_EXT_print(b, es, 0, 0));
    emit_mem("ext.asid.print.out", b);
    out_int("ext.asid.print.indent", X509V3_EXT_print(b, es, 0, 2));
    emit_mem("ext.asid.print.indent.out", b);

    ERR_clear_error();
    eu = X509V3_EXT_i2d(1000000, 0, addr);
    out_ptr("ext.unknown_nid", eu);
    out_err("ext.unknown_nid.err");

    X509_EXTENSION_free(ea);
    X509_EXTENSION_free(ec);
    X509_EXTENSION_free(es);
    X509_EXTENSION_free(eu);
    BIO_free(b);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.5 -- `crypto/x509/v3_utl.c`'s `X509V3_add_value_int`.
 * --------------------------------------------------------------------------------------------- */

static void drive_v3_utl(void)
{
    STACK_OF(CONF_VALUE) *sk = NULL;
    ASN1_INTEGER *ai = mk_int(7);
    CONF_VALUE *v;

    ERR_clear_error();
    out_int("add_value_int.ret", X509V3_add_value_int("pathlen", ai, &sk));
    out_err("add_value_int.ret.err");
    out_int("add_value_int.count", sk != NULL ? sk_CONF_VALUE_num(sk) : -1);
    v = sk != NULL ? sk_CONF_VALUE_value(sk, 0) : NULL;
    printf("add_value_int.name=%s\n", v != NULL ? v->name : "(null)");
    printf("add_value_int.value=%s\n", v != NULL ? v->value : "(null)");

    /* A NULL `aint` answers 1 without touching the list. */
    out_int("add_value_int.null_aint", X509V3_add_value_int("x", NULL, &sk));
    out_int("add_value_int.count.after", sk != NULL ? sk_CONF_VALUE_num(sk) : -1);

    ASN1_INTEGER_free(ai);
    sk_CONF_VALUE_pop_free(sk, X509V3_conf_free);
}

/* ---------------------------------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------------------------------- */

int main(void)
{
    IPAddrBlocks *addr;
    ASIdentifiers *asid;

    setvbuf(stdout, NULL, _IOLBF, 0);
    ERR_clear_error();

    addr = addr_blocks_fixture();
    drive_addr_values(addr);
    drive_addr_items(addr);
    drive_addr_safi();
    drive_addr_canonize_split();
    drive_addr_subset();
    drive_addr_refusals();

    asid = asid_fixture();
    drive_asid_values(asid);
    drive_asid_items(asid);
    drive_asid_inherit();
    drive_asid_canonize_adjacent();
    drive_asid_refusals();
    drive_asid_subset();

    drive_ext_i2d(addr, asid);
    drive_v3_utl();

    sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);
    ASIdentifiers_free(asid);
    return 0;
}
