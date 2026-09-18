/*
 * RT-PROVIDER-REF -- reference basis for the libctx/provider plane's unexercised entries,
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
extern void ASN1_add_oid_module(void);
extern void CONF_modules_load_file_ex(void);
extern void OPENSSL_thread_stop_ex(void);
extern void OSSL_PROVIDER_try_load(void);
extern void OSSL_PROVIDER_try_load_ex(void);

static const void *volatile refs[] = {
    (const void *) ASN1_add_oid_module,
    (const void *) CONF_modules_load_file_ex,
    (const void *) OPENSSL_thread_stop_ex,
    (const void *) OSSL_PROVIDER_try_load,
    (const void *) OSSL_PROVIDER_try_load_ex,
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
