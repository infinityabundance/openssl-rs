/*
 * RT-KEYFORMAT-REF -- reference basis for the key-format plane's inherited
 * entries, and nothing more.
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
 * The eighty-seven names below are this stratum's inherited `implemented` exports --
 * the thirty-eight `encoder.h` and forty-one `decoder.h` exports Phase 8's 8.8/8.9
 * chain landed (D362-D367), and the eight `pkcs12.h` decryption and PKCS#8 names D368
 * landed -- as `forensics/phase10-obligations.json` records them. **Phase 10 landed
 * none of them**, and it can run no behavioural court for them yet: their providers'
 * codec rows are unimplemented and a probe that called one would abort the candidate.
 * So this is the one edge the court coverage atlas holds for each on the commit that
 * puts the stratum's ledger in scope, and it claims reference, not behaviour
 * (docs/PHASE-10-SUBPHASES.md section 4.3).
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
extern void OSSL_DECODER_CTX_add_decoder(void);
extern void OSSL_DECODER_CTX_add_extra(void);
extern void OSSL_DECODER_CTX_free(void);
extern void OSSL_DECODER_CTX_get_cleanup(void);
extern void OSSL_DECODER_CTX_get_construct(void);
extern void OSSL_DECODER_CTX_get_construct_data(void);
extern void OSSL_DECODER_CTX_get_num_decoders(void);
extern void OSSL_DECODER_CTX_new(void);
extern void OSSL_DECODER_CTX_new_for_pkey(void);
extern void OSSL_DECODER_CTX_set_cleanup(void);
extern void OSSL_DECODER_CTX_set_construct(void);
extern void OSSL_DECODER_CTX_set_construct_data(void);
extern void OSSL_DECODER_CTX_set_input_structure(void);
extern void OSSL_DECODER_CTX_set_input_type(void);
extern void OSSL_DECODER_CTX_set_params(void);
extern void OSSL_DECODER_CTX_set_passphrase(void);
extern void OSSL_DECODER_CTX_set_passphrase_cb(void);
extern void OSSL_DECODER_CTX_set_passphrase_ui(void);
extern void OSSL_DECODER_CTX_set_pem_password_cb(void);
extern void OSSL_DECODER_CTX_set_selection(void);
extern void OSSL_DECODER_INSTANCE_get_decoder(void);
extern void OSSL_DECODER_INSTANCE_get_decoder_ctx(void);
extern void OSSL_DECODER_INSTANCE_get_input_structure(void);
extern void OSSL_DECODER_INSTANCE_get_input_type(void);
extern void OSSL_DECODER_do_all_provided(void);
extern void OSSL_DECODER_export(void);
extern void OSSL_DECODER_fetch(void);
extern void OSSL_DECODER_free(void);
extern void OSSL_DECODER_from_bio(void);
extern void OSSL_DECODER_from_data(void);
extern void OSSL_DECODER_from_fp(void);
extern void OSSL_DECODER_get0_description(void);
extern void OSSL_DECODER_get0_name(void);
extern void OSSL_DECODER_get0_properties(void);
extern void OSSL_DECODER_get0_provider(void);
extern void OSSL_DECODER_get_params(void);
extern void OSSL_DECODER_gettable_params(void);
extern void OSSL_DECODER_is_a(void);
extern void OSSL_DECODER_names_do_all(void);
extern void OSSL_DECODER_settable_ctx_params(void);
extern void OSSL_DECODER_up_ref(void);
extern void OSSL_ENCODER_CTX_add_encoder(void);
extern void OSSL_ENCODER_CTX_add_extra(void);
extern void OSSL_ENCODER_CTX_free(void);
extern void OSSL_ENCODER_CTX_get_num_encoders(void);
extern void OSSL_ENCODER_CTX_new(void);
extern void OSSL_ENCODER_CTX_new_for_pkey(void);
extern void OSSL_ENCODER_CTX_set_cipher(void);
extern void OSSL_ENCODER_CTX_set_cleanup(void);
extern void OSSL_ENCODER_CTX_set_construct(void);
extern void OSSL_ENCODER_CTX_set_construct_data(void);
extern void OSSL_ENCODER_CTX_set_output_structure(void);
extern void OSSL_ENCODER_CTX_set_output_type(void);
extern void OSSL_ENCODER_CTX_set_params(void);
extern void OSSL_ENCODER_CTX_set_passphrase(void);
extern void OSSL_ENCODER_CTX_set_passphrase_cb(void);
extern void OSSL_ENCODER_CTX_set_passphrase_ui(void);
extern void OSSL_ENCODER_CTX_set_pem_password_cb(void);
extern void OSSL_ENCODER_CTX_set_selection(void);
extern void OSSL_ENCODER_INSTANCE_get_encoder(void);
extern void OSSL_ENCODER_INSTANCE_get_encoder_ctx(void);
extern void OSSL_ENCODER_INSTANCE_get_output_structure(void);
extern void OSSL_ENCODER_INSTANCE_get_output_type(void);
extern void OSSL_ENCODER_do_all_provided(void);
extern void OSSL_ENCODER_fetch(void);
extern void OSSL_ENCODER_free(void);
extern void OSSL_ENCODER_get0_description(void);
extern void OSSL_ENCODER_get0_name(void);
extern void OSSL_ENCODER_get0_properties(void);
extern void OSSL_ENCODER_get0_provider(void);
extern void OSSL_ENCODER_get_params(void);
extern void OSSL_ENCODER_gettable_params(void);
extern void OSSL_ENCODER_is_a(void);
extern void OSSL_ENCODER_names_do_all(void);
extern void OSSL_ENCODER_settable_ctx_params(void);
extern void OSSL_ENCODER_to_bio(void);
extern void OSSL_ENCODER_to_data(void);
extern void OSSL_ENCODER_to_fp(void);
extern void OSSL_ENCODER_up_ref(void);
extern void PKCS12_item_decrypt_d2i(void);
extern void PKCS12_item_decrypt_d2i_ex(void);
extern void PKCS12_item_i2d_encrypt(void);
extern void PKCS12_item_i2d_encrypt_ex(void);
extern void PKCS12_pbe_crypt(void);
extern void PKCS12_pbe_crypt_ex(void);
extern void PKCS8_decrypt(void);
extern void PKCS8_decrypt_ex(void);

static const void *volatile refs[] = {
    (const void *) OSSL_DECODER_CTX_add_decoder,
    (const void *) OSSL_DECODER_CTX_add_extra,
    (const void *) OSSL_DECODER_CTX_free,
    (const void *) OSSL_DECODER_CTX_get_cleanup,
    (const void *) OSSL_DECODER_CTX_get_construct,
    (const void *) OSSL_DECODER_CTX_get_construct_data,
    (const void *) OSSL_DECODER_CTX_get_num_decoders,
    (const void *) OSSL_DECODER_CTX_new,
    (const void *) OSSL_DECODER_CTX_new_for_pkey,
    (const void *) OSSL_DECODER_CTX_set_cleanup,
    (const void *) OSSL_DECODER_CTX_set_construct,
    (const void *) OSSL_DECODER_CTX_set_construct_data,
    (const void *) OSSL_DECODER_CTX_set_input_structure,
    (const void *) OSSL_DECODER_CTX_set_input_type,
    (const void *) OSSL_DECODER_CTX_set_params,
    (const void *) OSSL_DECODER_CTX_set_passphrase,
    (const void *) OSSL_DECODER_CTX_set_passphrase_cb,
    (const void *) OSSL_DECODER_CTX_set_passphrase_ui,
    (const void *) OSSL_DECODER_CTX_set_pem_password_cb,
    (const void *) OSSL_DECODER_CTX_set_selection,
    (const void *) OSSL_DECODER_INSTANCE_get_decoder,
    (const void *) OSSL_DECODER_INSTANCE_get_decoder_ctx,
    (const void *) OSSL_DECODER_INSTANCE_get_input_structure,
    (const void *) OSSL_DECODER_INSTANCE_get_input_type,
    (const void *) OSSL_DECODER_do_all_provided,
    (const void *) OSSL_DECODER_export,
    (const void *) OSSL_DECODER_fetch,
    (const void *) OSSL_DECODER_free,
    (const void *) OSSL_DECODER_from_bio,
    (const void *) OSSL_DECODER_from_data,
    (const void *) OSSL_DECODER_from_fp,
    (const void *) OSSL_DECODER_get0_description,
    (const void *) OSSL_DECODER_get0_name,
    (const void *) OSSL_DECODER_get0_properties,
    (const void *) OSSL_DECODER_get0_provider,
    (const void *) OSSL_DECODER_get_params,
    (const void *) OSSL_DECODER_gettable_params,
    (const void *) OSSL_DECODER_is_a,
    (const void *) OSSL_DECODER_names_do_all,
    (const void *) OSSL_DECODER_settable_ctx_params,
    (const void *) OSSL_DECODER_up_ref,
    (const void *) OSSL_ENCODER_CTX_add_encoder,
    (const void *) OSSL_ENCODER_CTX_add_extra,
    (const void *) OSSL_ENCODER_CTX_free,
    (const void *) OSSL_ENCODER_CTX_get_num_encoders,
    (const void *) OSSL_ENCODER_CTX_new,
    (const void *) OSSL_ENCODER_CTX_new_for_pkey,
    (const void *) OSSL_ENCODER_CTX_set_cipher,
    (const void *) OSSL_ENCODER_CTX_set_cleanup,
    (const void *) OSSL_ENCODER_CTX_set_construct,
    (const void *) OSSL_ENCODER_CTX_set_construct_data,
    (const void *) OSSL_ENCODER_CTX_set_output_structure,
    (const void *) OSSL_ENCODER_CTX_set_output_type,
    (const void *) OSSL_ENCODER_CTX_set_params,
    (const void *) OSSL_ENCODER_CTX_set_passphrase,
    (const void *) OSSL_ENCODER_CTX_set_passphrase_cb,
    (const void *) OSSL_ENCODER_CTX_set_passphrase_ui,
    (const void *) OSSL_ENCODER_CTX_set_pem_password_cb,
    (const void *) OSSL_ENCODER_CTX_set_selection,
    (const void *) OSSL_ENCODER_INSTANCE_get_encoder,
    (const void *) OSSL_ENCODER_INSTANCE_get_encoder_ctx,
    (const void *) OSSL_ENCODER_INSTANCE_get_output_structure,
    (const void *) OSSL_ENCODER_INSTANCE_get_output_type,
    (const void *) OSSL_ENCODER_do_all_provided,
    (const void *) OSSL_ENCODER_fetch,
    (const void *) OSSL_ENCODER_free,
    (const void *) OSSL_ENCODER_get0_description,
    (const void *) OSSL_ENCODER_get0_name,
    (const void *) OSSL_ENCODER_get0_properties,
    (const void *) OSSL_ENCODER_get0_provider,
    (const void *) OSSL_ENCODER_get_params,
    (const void *) OSSL_ENCODER_gettable_params,
    (const void *) OSSL_ENCODER_is_a,
    (const void *) OSSL_ENCODER_names_do_all,
    (const void *) OSSL_ENCODER_settable_ctx_params,
    (const void *) OSSL_ENCODER_to_bio,
    (const void *) OSSL_ENCODER_to_data,
    (const void *) OSSL_ENCODER_to_fp,
    (const void *) OSSL_ENCODER_up_ref,
    (const void *) PKCS12_item_decrypt_d2i,
    (const void *) PKCS12_item_decrypt_d2i_ex,
    (const void *) PKCS12_item_i2d_encrypt,
    (const void *) PKCS12_item_i2d_encrypt_ex,
    (const void *) PKCS12_pbe_crypt,
    (const void *) PKCS12_pbe_crypt_ex,
    (const void *) PKCS8_decrypt,
    (const void *) PKCS8_decrypt_ex,
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
