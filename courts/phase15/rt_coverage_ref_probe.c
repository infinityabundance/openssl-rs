/*
 * RT-PHASE15-REF -- the reference basis the QUIC / ECH stratum requires, and
 * nothing more.
 *
 * This probe exists to answer exactly one question the court coverage atlas asks:
 * *is this export referenced by a probe that ran and produced a transcript?* It
 * takes each symbol's address through a `volatile` table, prints one
 * `coverage_ref.N=nonnull` line per symbol, and stops. **It does not call any of
 * them, and therefore does not claim any behaviour about them.** A symbol covered
 * only here is recorded in `forensics/atlas/court-coverage.json` at basis
 * `referenced`, never `called`, and the atlas's `claim` says the weaker thing on
 * purpose: the name is referenced by a probe that ran, which is not the same as
 * every arm of the name having been driven. See docs/DECISIONS.md D199.
 *
 * The three names below are the whole of the stratum's atlas-owned universe,
 * `forensics/atlas/symbol-ownership.json`'s `owner_phase == 15` rows, all declared
 * in `quic.h`: `OSSL_QUIC_client_method`, `OSSL_QUIC_client_thread_method` and
 * `OSSL_QUIC_server_method`. Phase 14's plan and seal name them as Phase 15's by
 * their declaring header, and Phase 14 landed none of them. At activation the
 * candidate distribution still *defined* all three through the Phase 2 ABI
 * scaffold (`artifacts/phase2/shell/libssl.shell.rs`), which aborts when one is
 * called, so the link proved each name existed while claiming nothing about its
 * behaviour; taking an address rather than calling is what kept that safe. Once
 * 15.1 lands `src/ssl/quic/quic_method.rs` the candidate defines them for real,
 * and the same probe still takes addresses rather than calling.
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
extern void OSSL_QUIC_client_method(void);
extern void OSSL_QUIC_client_thread_method(void);
extern void OSSL_QUIC_server_method(void);

static const void *volatile refs[] = {
    (const void *) OSSL_QUIC_client_method,
    (const void *) OSSL_QUIC_client_thread_method,
    (const void *) OSSL_QUIC_server_method,
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
