/*
 * RT-BIO-CONF-REF -- reference basis for the BIO/CONF plane's unexercised entries,
 * and nothing more.
 *
 * This probe exists to answer exactly one question the court coverage atlas asks:
 * *is this implemented export referenced by a probe that ran and produced a
 * transcript?* It takes each remaining symbol's address through a `volatile` table,
 * prints one `name=nonnull` line per symbol, and stops. **It does not call any of
 * them, and therefore does not claim any behaviour about them.** A symbol covered
 * only here is recorded in `forensics/atlas/court-coverage.json` at basis
 * `referenced`, never `called`, and the atlas's `claim` says the weaker thing on
 * purpose: the name is referenced by a probe that ran, which is not the same as
 * every arm of the name having been driven. See docs/DECISIONS.md D199.
 *
 * It is a probe rather than a source scan because a source scan cannot tell a call
 * from a comment, and because the dynamic linker resolves the reference only if the
 * candidate distribution actually defines the name -- the link is the evidence.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

/* Declared here rather than through the installed headers: the headers a given
 * symbol is promised by are not this probe's subject, and a self-declaration cannot
 * be reshaped by a header the candidate has not finished. The link is what proves
 * the name exists. */
extern void BIO_copy_next_retry(void);
extern void BIO_ctrl_get_write_guarantee(void);
extern void BIO_do_connect_retry(void);
extern void BIO_dump_cb(void);
extern void BIO_dump_fp(void);
extern void BIO_dump_indent_cb(void);
extern void BIO_dump_indent_fp(void);
extern void BIO_get_callback_ex(void);
extern void BIO_get_rpoll_descriptor(void);
extern void BIO_get_wpoll_descriptor(void);
extern void BIO_meth_get_gets(void);
extern void BIO_meth_get_recvmmsg(void);
extern void BIO_meth_get_sendmmsg(void);
extern void BIO_meth_set_gets(void);
extern void BIO_meth_set_recvmmsg(void);
extern void BIO_meth_set_sendmmsg(void);
extern void BIO_meth_set_write_ex(void);
extern void BIO_new_ex(void);
extern void BIO_socket_ioctl(void);
extern void BIO_vprintf(void);
extern void BIO_vsnprintf(void);
extern void BIO_wait(void);
extern void BUF_reverse(void);
extern void COMP_CTX_get_method(void);
extern void COMP_CTX_get_type(void);
extern void COMP_compress_block(void);
extern void COMP_expand_block(void);
extern void CONF_dump_fp(void);
extern void CONF_load_bio(void);
extern void CONF_load_fp(void);
extern void CONF_set_default_method(void);
extern void CONF_set_nconf(void);
extern void NCONF_dump_fp(void);
extern void NCONF_load_fp(void);
extern void OPENSSL_INIT_set_config_appname(void);
extern void OPENSSL_LH_node_stats(void);

static const void *volatile refs[] = {
    (const void *) BIO_copy_next_retry,
    (const void *) BIO_ctrl_get_write_guarantee,
    (const void *) BIO_do_connect_retry,
    (const void *) BIO_dump_cb,
    (const void *) BIO_dump_fp,
    (const void *) BIO_dump_indent_cb,
    (const void *) BIO_dump_indent_fp,
    (const void *) BIO_get_callback_ex,
    (const void *) BIO_get_rpoll_descriptor,
    (const void *) BIO_get_wpoll_descriptor,
    (const void *) BIO_meth_get_gets,
    (const void *) BIO_meth_get_recvmmsg,
    (const void *) BIO_meth_get_sendmmsg,
    (const void *) BIO_meth_set_gets,
    (const void *) BIO_meth_set_recvmmsg,
    (const void *) BIO_meth_set_sendmmsg,
    (const void *) BIO_meth_set_write_ex,
    (const void *) BIO_new_ex,
    (const void *) BIO_socket_ioctl,
    (const void *) BIO_vprintf,
    (const void *) BIO_vsnprintf,
    (const void *) BIO_wait,
    (const void *) BUF_reverse,
    (const void *) COMP_CTX_get_method,
    (const void *) COMP_CTX_get_type,
    (const void *) COMP_compress_block,
    (const void *) COMP_expand_block,
    (const void *) CONF_dump_fp,
    (const void *) CONF_load_bio,
    (const void *) CONF_load_fp,
    (const void *) CONF_set_default_method,
    (const void *) CONF_set_nconf,
    (const void *) NCONF_dump_fp,
    (const void *) NCONF_load_fp,
    (const void *) OPENSSL_INIT_set_config_appname,
    (const void *) OPENSSL_LH_node_stats,
};

int main(void)
{
    size_t i;

    setvbuf(stdout, NULL, _IOLBF, 0);
    for (i = 0; i < sizeof refs / sizeof refs[0]; i++)
        printf("coverage_ref.%zu=%s\n", i,
               refs[i] == NULL ? "NULL" : "nonnull");
    return 0;
}
