/*
 * RT-BN-ASN1-REF -- reference basis for the BN/ASN.1 plane's unexercised entries,
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
extern void ASN1_BMPSTRING_free(void);
extern void ASN1_BMPSTRING_new(void);
extern void ASN1_ENUMERATED_get_int64(void);
extern void ASN1_ENUMERATED_set_int64(void);
extern void ASN1_GENERALSTRING_free(void);
extern void ASN1_GENERALSTRING_new(void);
extern void ASN1_IA5STRING_free(void);
extern void ASN1_INTEGER_dup(void);
extern void ASN1_SEQUENCE_ANY_it(void);
extern void ASN1_SET_ANY_it(void);
extern void ASN1_T61STRING_free(void);
extern void ASN1_T61STRING_new(void);
extern void ASN1_TIME_set(void);
extern void ASN1_TYPE_cmp(void);
extern void ASN1_TYPE_pack_sequence(void);
extern void ASN1_TYPE_set1(void);
extern void ASN1_TYPE_unpack_sequence(void);
extern void ASN1_UNIVERSALSTRING_free(void);
extern void ASN1_UNIVERSALSTRING_new(void);
extern void ASN1_VISIBLESTRING_free(void);
extern void ASN1_VISIBLESTRING_new(void);
extern void ASN1_d2i_bio(void);
extern void ASN1_d2i_fp(void);
extern void ASN1_dup(void);
extern void ASN1_i2d_bio(void);
extern void ASN1_i2d_fp(void);
extern void ASN1_item_d2i_bio(void);
extern void ASN1_item_d2i_bio_ex(void);
extern void ASN1_item_d2i_ex(void);
extern void ASN1_item_d2i_fp(void);
extern void ASN1_item_d2i_fp_ex(void);
extern void ASN1_item_dup(void);
extern void ASN1_item_ex_d2i(void);
extern void ASN1_item_ex_free(void);
extern void ASN1_item_ex_i2d(void);
extern void ASN1_item_ex_new(void);
extern void ASN1_item_i2d_bio(void);
extern void ASN1_item_i2d_fp(void);
extern void ASN1_item_i2d_mem_bio(void);
extern void ASN1_item_ndef_i2d(void);
extern void ASN1_item_new_ex(void);
extern void ASN1_item_pack(void);
extern void ASN1_item_unpack(void);
extern void ASN1_item_unpack_ex(void);
extern void BN_BLINDING_invert(void);
extern void BN_BLINDING_set_current_thread(void);
extern void BN_CTX_new_ex(void);
extern void BN_CTX_secure_new(void);
extern void BN_CTX_secure_new_ex(void);
extern void BN_MONT_CTX_copy(void);
extern void BN_MONT_CTX_set_locked(void);
extern void BN_bn2nativepad(void);
extern void BN_clear_bit(void);
extern void BN_get_params(void);
extern void BN_mod_exp_mont_consttime_x2(void);
extern void BN_mpi2bn(void);
extern void BN_native2bn(void);
extern void BN_options(void);
extern void BN_print(void);
extern void BN_print_fp(void);
extern void BN_secure_new(void);
extern void BN_security_bits(void);
extern void BN_set_bit(void);
extern void BN_set_params(void);
extern void BN_signed_bin2bn(void);
extern void BN_to_ASN1_ENUMERATED(void);
extern void BN_value_one(void);
extern void BN_with_flags(void);
extern void BN_zero_ex(void);
extern void CBIGNUM_it(void);
extern void DIRECTORYSTRING_free(void);
extern void DIRECTORYSTRING_new(void);
extern void DISPLAYTEXT_free(void);
extern void DISPLAYTEXT_new(void);
extern void UINT64_it(void);
extern void ZINT64_it(void);
extern void ZUINT32_it(void);
extern void ZUINT64_it(void);
extern void asn1_d2i_read_bio(void);
extern void d2i_ASN1_GENERALSTRING(void);
extern void i2d_ASN1_BMPSTRING(void);
extern void i2d_ASN1_ENUMERATED(void);
extern void i2d_ASN1_GENERALIZEDTIME(void);
extern void i2d_ASN1_GENERALSTRING(void);
extern void i2d_ASN1_IA5STRING(void);
extern void i2d_ASN1_PRINTABLE(void);
extern void i2d_ASN1_PRINTABLESTRING(void);
extern void i2d_ASN1_T61STRING(void);
extern void i2d_ASN1_TIME(void);
extern void i2d_ASN1_UNIVERSALSTRING(void);
extern void i2d_ASN1_UTCTIME(void);
extern void i2d_ASN1_VISIBLESTRING(void);
extern void i2d_DIRECTORYSTRING(void);
extern void i2d_DISPLAYTEXT(void);

static const void *volatile refs[] = {
    (const void *) ASN1_BMPSTRING_free,
    (const void *) ASN1_BMPSTRING_new,
    (const void *) ASN1_ENUMERATED_get_int64,
    (const void *) ASN1_ENUMERATED_set_int64,
    (const void *) ASN1_GENERALSTRING_free,
    (const void *) ASN1_GENERALSTRING_new,
    (const void *) ASN1_IA5STRING_free,
    (const void *) ASN1_INTEGER_dup,
    (const void *) ASN1_SEQUENCE_ANY_it,
    (const void *) ASN1_SET_ANY_it,
    (const void *) ASN1_T61STRING_free,
    (const void *) ASN1_T61STRING_new,
    (const void *) ASN1_TIME_set,
    (const void *) ASN1_TYPE_cmp,
    (const void *) ASN1_TYPE_pack_sequence,
    (const void *) ASN1_TYPE_set1,
    (const void *) ASN1_TYPE_unpack_sequence,
    (const void *) ASN1_UNIVERSALSTRING_free,
    (const void *) ASN1_UNIVERSALSTRING_new,
    (const void *) ASN1_VISIBLESTRING_free,
    (const void *) ASN1_VISIBLESTRING_new,
    (const void *) ASN1_d2i_bio,
    (const void *) ASN1_d2i_fp,
    (const void *) ASN1_dup,
    (const void *) ASN1_i2d_bio,
    (const void *) ASN1_i2d_fp,
    (const void *) ASN1_item_d2i_bio,
    (const void *) ASN1_item_d2i_bio_ex,
    (const void *) ASN1_item_d2i_ex,
    (const void *) ASN1_item_d2i_fp,
    (const void *) ASN1_item_d2i_fp_ex,
    (const void *) ASN1_item_dup,
    (const void *) ASN1_item_ex_d2i,
    (const void *) ASN1_item_ex_free,
    (const void *) ASN1_item_ex_i2d,
    (const void *) ASN1_item_ex_new,
    (const void *) ASN1_item_i2d_bio,
    (const void *) ASN1_item_i2d_fp,
    (const void *) ASN1_item_i2d_mem_bio,
    (const void *) ASN1_item_ndef_i2d,
    (const void *) ASN1_item_new_ex,
    (const void *) ASN1_item_pack,
    (const void *) ASN1_item_unpack,
    (const void *) ASN1_item_unpack_ex,
    (const void *) BN_BLINDING_invert,
    (const void *) BN_BLINDING_set_current_thread,
    (const void *) BN_CTX_new_ex,
    (const void *) BN_CTX_secure_new,
    (const void *) BN_CTX_secure_new_ex,
    (const void *) BN_MONT_CTX_copy,
    (const void *) BN_MONT_CTX_set_locked,
    (const void *) BN_bn2nativepad,
    (const void *) BN_clear_bit,
    (const void *) BN_get_params,
    (const void *) BN_mod_exp_mont_consttime_x2,
    (const void *) BN_mpi2bn,
    (const void *) BN_native2bn,
    (const void *) BN_options,
    (const void *) BN_print,
    (const void *) BN_print_fp,
    (const void *) BN_secure_new,
    (const void *) BN_security_bits,
    (const void *) BN_set_bit,
    (const void *) BN_set_params,
    (const void *) BN_signed_bin2bn,
    (const void *) BN_to_ASN1_ENUMERATED,
    (const void *) BN_value_one,
    (const void *) BN_with_flags,
    (const void *) BN_zero_ex,
    (const void *) CBIGNUM_it,
    (const void *) DIRECTORYSTRING_free,
    (const void *) DIRECTORYSTRING_new,
    (const void *) DISPLAYTEXT_free,
    (const void *) DISPLAYTEXT_new,
    (const void *) UINT64_it,
    (const void *) ZINT64_it,
    (const void *) ZUINT32_it,
    (const void *) ZUINT64_it,
    (const void *) asn1_d2i_read_bio,
    (const void *) d2i_ASN1_GENERALSTRING,
    (const void *) i2d_ASN1_BMPSTRING,
    (const void *) i2d_ASN1_ENUMERATED,
    (const void *) i2d_ASN1_GENERALIZEDTIME,
    (const void *) i2d_ASN1_GENERALSTRING,
    (const void *) i2d_ASN1_IA5STRING,
    (const void *) i2d_ASN1_PRINTABLE,
    (const void *) i2d_ASN1_PRINTABLESTRING,
    (const void *) i2d_ASN1_T61STRING,
    (const void *) i2d_ASN1_TIME,
    (const void *) i2d_ASN1_UNIVERSALSTRING,
    (const void *) i2d_ASN1_UTCTIME,
    (const void *) i2d_ASN1_VISIBLESTRING,
    (const void *) i2d_DIRECTORYSTRING,
    (const void *) i2d_DISPLAYTEXT,
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
