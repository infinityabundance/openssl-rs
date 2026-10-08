/*
 * 24.10 hostility probe: a **custom BIO** — a caller-supplied BIO_METHOD via the BIO_meth_* family,
 * with the create/ctrl/write/read callbacks, the per-BIO data pointer, and the reference-counted
 * ownership (`BIO_up_ref` + two `BIO_free`s). It exercises the BIO method/callback contract a custom
 * consumer relies on, which the counted P1000 families' imported-symbol union does not reach.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hostility_common.h"
#include <openssl/bio.h>

static const char *PAYLOAD = "custom-bio-payload";

static int cb_write(BIO *b, const char *in, int inl)
{
    BIO_set_data(b, (void *)in);
    BIO_set_init(b, 1);
    return inl;
}

static int cb_read(BIO *b, char *out, int outl)
{
    (void)b;
    (void)out;
    (void)outl;
    return 0;
}

static long cb_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    (void)b;
    (void)num;
    (void)ptr;
    return (cmd == BIO_CTRL_FLUSH) ? 1L : 0L;
}

static int cb_create(BIO *b)
{
    BIO_set_init(b, 1);
    BIO_set_data(b, NULL);
    return 1;
}

static int cb_destroy(BIO *b)
{
    (void)b;
    return 1;
}

int main(void)
{
    hostility_banner("custom-bio");
    BIO_METHOD *m = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "hostility-custom");
    if (m == NULL)
        hostility_fail("BIO_meth_new");
    if (!BIO_meth_set_write(m, cb_write))
        hostility_fail("BIO_meth_set_write");
    if (!BIO_meth_set_read(m, cb_read))
        hostility_fail("BIO_meth_set_read");
    if (!BIO_meth_set_ctrl(m, cb_ctrl))
        hostility_fail("BIO_meth_set_ctrl");
    if (!BIO_meth_set_create(m, cb_create))
        hostility_fail("BIO_meth_set_create");
    if (!BIO_meth_set_destroy(m, cb_destroy))
        hostility_fail("BIO_meth_set_destroy");
    if (BIO_meth_get_write(m) != cb_write)
        hostility_fail("BIO_meth_get_write");
    if (BIO_meth_get_read(m) != cb_read)
        hostility_fail("BIO_meth_get_read");
    if (BIO_meth_get_ctrl(m) != cb_ctrl)
        hostility_fail("BIO_meth_get_ctrl");
    if (BIO_meth_get_create(m) != cb_create)
        hostility_fail("BIO_meth_get_create");
    if (BIO_meth_get_destroy(m) != cb_destroy)
        hostility_fail("BIO_meth_get_destroy");
    int new_index = BIO_get_new_index();
    if (new_index < 0)
        hostility_fail("BIO_get_new_index");

    BIO *b = BIO_new(m);
    if (b == NULL)
        hostility_fail("BIO_new");
    BIO_set_callback_ex(b, NULL);
    if (!BIO_up_ref(b))
        hostility_fail("BIO_up_ref");
    int n = BIO_write(b, PAYLOAD, (int)strlen(PAYLOAD));
    if (n != (int)strlen(PAYLOAD))
        hostility_fail("BIO_write");
    const void *d = BIO_get_data(b);
    if (d != (const void *)PAYLOAD)
        hostility_fail("BIO_get_data roundtrip");
    if (BIO_read(b, (char[8]){0}, 0) != 0)
        hostility_fail("BIO_read");
    if (BIO_ctrl(b, BIO_CTRL_FLUSH, 0, NULL) != 1)
        hostility_fail("BIO_ctrl");
    BIO_free(b);
    BIO_free(b);
    BIO_meth_free(m);
    printf("bio_write=%d\n", n);
    printf("bio_new_index=%d\n", new_index);
    hostility_ok();
    return 0;
}
