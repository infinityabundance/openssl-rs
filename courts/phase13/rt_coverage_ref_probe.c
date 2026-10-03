/*
 * RT-PHASE13-REF -- the reference basis the legacy/deprecated-compatibility
 * stratum's court coverage needs, and nothing more.
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
 * The 127 names below are the stratum's `implemented` exports this reference basis
 * covers, and every one of them is a *pre-activation* landing: 61 of the `ENGINE_*`
 * object, accessor and table surface plus the whole of the 62-name `UI_*` framework
 * (123 atlas-owned exports, landed by the earlier strata as substrate they needed)
 * and the four Phase 7 -> 13 `PEM_read[_bio]_PrivateKey` spellings (Phase 8 landed
 * them, D369). No unit of the stratum's own has landed yet, so this is the only
 * court 13.0 can register; the plan's behavioural courts are named in
 * `forensics/tools/phase13_courts.py`'s `PENDING_COURTS` with the subphase that
 * brings each.
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
extern void ENGINE_add(void);
extern void ENGINE_cmd_is_executable(void);
extern void ENGINE_ctrl(void);
extern void ENGINE_ctrl_cmd(void);
extern void ENGINE_ctrl_cmd_string(void);
extern void ENGINE_finish(void);
extern void ENGINE_free(void);
extern void ENGINE_get_cmd_defns(void);
extern void ENGINE_get_ctrl_function(void);
extern void ENGINE_get_destroy_function(void);
extern void ENGINE_get_digest(void);
extern void ENGINE_get_digest_engine(void);
extern void ENGINE_get_digests(void);
extern void ENGINE_get_ex_data(void);
extern void ENGINE_get_finish_function(void);
extern void ENGINE_get_first(void);
extern void ENGINE_get_flags(void);
extern void ENGINE_get_id(void);
extern void ENGINE_get_init_function(void);
extern void ENGINE_get_last(void);
extern void ENGINE_get_name(void);
extern void ENGINE_get_next(void);
extern void ENGINE_get_pkey_asn1_meth(void);
extern void ENGINE_get_pkey_asn1_meth_engine(void);
extern void ENGINE_get_pkey_asn1_meth_str(void);
extern void ENGINE_get_pkey_asn1_meths(void);
extern void ENGINE_get_pkey_meth_engine(void);
extern void ENGINE_get_pkey_meths(void);
extern void ENGINE_get_prev(void);
extern void ENGINE_get_static_state(void);
extern void ENGINE_get_table_flags(void);
extern void ENGINE_init(void);
extern void ENGINE_new(void);
extern void ENGINE_pkey_asn1_find_str(void);
extern void ENGINE_register_all_digests(void);
extern void ENGINE_register_all_pkey_asn1_meths(void);
extern void ENGINE_register_all_pkey_meths(void);
extern void ENGINE_register_digests(void);
extern void ENGINE_register_pkey_asn1_meths(void);
extern void ENGINE_register_pkey_meths(void);
extern void ENGINE_remove(void);
extern void ENGINE_set_cmd_defns(void);
extern void ENGINE_set_ctrl_function(void);
extern void ENGINE_set_default_digests(void);
extern void ENGINE_set_default_pkey_asn1_meths(void);
extern void ENGINE_set_default_pkey_meths(void);
extern void ENGINE_set_destroy_function(void);
extern void ENGINE_set_digests(void);
extern void ENGINE_set_ex_data(void);
extern void ENGINE_set_finish_function(void);
extern void ENGINE_set_flags(void);
extern void ENGINE_set_id(void);
extern void ENGINE_set_init_function(void);
extern void ENGINE_set_name(void);
extern void ENGINE_set_pkey_asn1_meths(void);
extern void ENGINE_set_pkey_meths(void);
extern void ENGINE_set_table_flags(void);
extern void ENGINE_unregister_digests(void);
extern void ENGINE_unregister_pkey_asn1_meths(void);
extern void ENGINE_unregister_pkey_meths(void);
extern void ENGINE_up_ref(void);
extern void PEM_read_PrivateKey(void);
extern void PEM_read_PrivateKey_ex(void);
extern void PEM_read_bio_PrivateKey(void);
extern void PEM_read_bio_PrivateKey_ex(void);
extern void UI_OpenSSL(void);
extern void UI_UTIL_read_pw(void);
extern void UI_UTIL_read_pw_string(void);
extern void UI_UTIL_wrap_read_pem_callback(void);
extern void UI_add_error_string(void);
extern void UI_add_info_string(void);
extern void UI_add_input_boolean(void);
extern void UI_add_input_string(void);
extern void UI_add_user_data(void);
extern void UI_add_verify_string(void);
extern void UI_construct_prompt(void);
extern void UI_create_method(void);
extern void UI_ctrl(void);
extern void UI_destroy_method(void);
extern void UI_dup_error_string(void);
extern void UI_dup_info_string(void);
extern void UI_dup_input_boolean(void);
extern void UI_dup_input_string(void);
extern void UI_dup_user_data(void);
extern void UI_dup_verify_string(void);
extern void UI_free(void);
extern void UI_get0_action_string(void);
extern void UI_get0_output_string(void);
extern void UI_get0_result(void);
extern void UI_get0_result_string(void);
extern void UI_get0_test_string(void);
extern void UI_get0_user_data(void);
extern void UI_get_default_method(void);
extern void UI_get_ex_data(void);
extern void UI_get_input_flags(void);
extern void UI_get_method(void);
extern void UI_get_result_length(void);
extern void UI_get_result_maxsize(void);
extern void UI_get_result_minsize(void);
extern void UI_get_result_string_length(void);
extern void UI_get_string_type(void);
extern void UI_method_get_closer(void);
extern void UI_method_get_data_destructor(void);
extern void UI_method_get_data_duplicator(void);
extern void UI_method_get_ex_data(void);
extern void UI_method_get_flusher(void);
extern void UI_method_get_opener(void);
extern void UI_method_get_prompt_constructor(void);
extern void UI_method_get_reader(void);
extern void UI_method_get_writer(void);
extern void UI_method_set_closer(void);
extern void UI_method_set_data_duplicator(void);
extern void UI_method_set_ex_data(void);
extern void UI_method_set_flusher(void);
extern void UI_method_set_opener(void);
extern void UI_method_set_prompt_constructor(void);
extern void UI_method_set_reader(void);
extern void UI_method_set_writer(void);
extern void UI_new(void);
extern void UI_new_method(void);
extern void UI_null(void);
extern void UI_process(void);
extern void UI_set_default_method(void);
extern void UI_set_ex_data(void);
extern void UI_set_method(void);
extern void UI_set_result(void);
extern void UI_set_result_ex(void);

static const void *volatile refs[] = {
    (const void *) ENGINE_add,
    (const void *) ENGINE_cmd_is_executable,
    (const void *) ENGINE_ctrl,
    (const void *) ENGINE_ctrl_cmd,
    (const void *) ENGINE_ctrl_cmd_string,
    (const void *) ENGINE_finish,
    (const void *) ENGINE_free,
    (const void *) ENGINE_get_cmd_defns,
    (const void *) ENGINE_get_ctrl_function,
    (const void *) ENGINE_get_destroy_function,
    (const void *) ENGINE_get_digest,
    (const void *) ENGINE_get_digest_engine,
    (const void *) ENGINE_get_digests,
    (const void *) ENGINE_get_ex_data,
    (const void *) ENGINE_get_finish_function,
    (const void *) ENGINE_get_first,
    (const void *) ENGINE_get_flags,
    (const void *) ENGINE_get_id,
    (const void *) ENGINE_get_init_function,
    (const void *) ENGINE_get_last,
    (const void *) ENGINE_get_name,
    (const void *) ENGINE_get_next,
    (const void *) ENGINE_get_pkey_asn1_meth,
    (const void *) ENGINE_get_pkey_asn1_meth_engine,
    (const void *) ENGINE_get_pkey_asn1_meth_str,
    (const void *) ENGINE_get_pkey_asn1_meths,
    (const void *) ENGINE_get_pkey_meth_engine,
    (const void *) ENGINE_get_pkey_meths,
    (const void *) ENGINE_get_prev,
    (const void *) ENGINE_get_static_state,
    (const void *) ENGINE_get_table_flags,
    (const void *) ENGINE_init,
    (const void *) ENGINE_new,
    (const void *) ENGINE_pkey_asn1_find_str,
    (const void *) ENGINE_register_all_digests,
    (const void *) ENGINE_register_all_pkey_asn1_meths,
    (const void *) ENGINE_register_all_pkey_meths,
    (const void *) ENGINE_register_digests,
    (const void *) ENGINE_register_pkey_asn1_meths,
    (const void *) ENGINE_register_pkey_meths,
    (const void *) ENGINE_remove,
    (const void *) ENGINE_set_cmd_defns,
    (const void *) ENGINE_set_ctrl_function,
    (const void *) ENGINE_set_default_digests,
    (const void *) ENGINE_set_default_pkey_asn1_meths,
    (const void *) ENGINE_set_default_pkey_meths,
    (const void *) ENGINE_set_destroy_function,
    (const void *) ENGINE_set_digests,
    (const void *) ENGINE_set_ex_data,
    (const void *) ENGINE_set_finish_function,
    (const void *) ENGINE_set_flags,
    (const void *) ENGINE_set_id,
    (const void *) ENGINE_set_init_function,
    (const void *) ENGINE_set_name,
    (const void *) ENGINE_set_pkey_asn1_meths,
    (const void *) ENGINE_set_pkey_meths,
    (const void *) ENGINE_set_table_flags,
    (const void *) ENGINE_unregister_digests,
    (const void *) ENGINE_unregister_pkey_asn1_meths,
    (const void *) ENGINE_unregister_pkey_meths,
    (const void *) ENGINE_up_ref,
    (const void *) PEM_read_PrivateKey,
    (const void *) PEM_read_PrivateKey_ex,
    (const void *) PEM_read_bio_PrivateKey,
    (const void *) PEM_read_bio_PrivateKey_ex,
    (const void *) UI_OpenSSL,
    (const void *) UI_UTIL_read_pw,
    (const void *) UI_UTIL_read_pw_string,
    (const void *) UI_UTIL_wrap_read_pem_callback,
    (const void *) UI_add_error_string,
    (const void *) UI_add_info_string,
    (const void *) UI_add_input_boolean,
    (const void *) UI_add_input_string,
    (const void *) UI_add_user_data,
    (const void *) UI_add_verify_string,
    (const void *) UI_construct_prompt,
    (const void *) UI_create_method,
    (const void *) UI_ctrl,
    (const void *) UI_destroy_method,
    (const void *) UI_dup_error_string,
    (const void *) UI_dup_info_string,
    (const void *) UI_dup_input_boolean,
    (const void *) UI_dup_input_string,
    (const void *) UI_dup_user_data,
    (const void *) UI_dup_verify_string,
    (const void *) UI_free,
    (const void *) UI_get0_action_string,
    (const void *) UI_get0_output_string,
    (const void *) UI_get0_result,
    (const void *) UI_get0_result_string,
    (const void *) UI_get0_test_string,
    (const void *) UI_get0_user_data,
    (const void *) UI_get_default_method,
    (const void *) UI_get_ex_data,
    (const void *) UI_get_input_flags,
    (const void *) UI_get_method,
    (const void *) UI_get_result_length,
    (const void *) UI_get_result_maxsize,
    (const void *) UI_get_result_minsize,
    (const void *) UI_get_result_string_length,
    (const void *) UI_get_string_type,
    (const void *) UI_method_get_closer,
    (const void *) UI_method_get_data_destructor,
    (const void *) UI_method_get_data_duplicator,
    (const void *) UI_method_get_ex_data,
    (const void *) UI_method_get_flusher,
    (const void *) UI_method_get_opener,
    (const void *) UI_method_get_prompt_constructor,
    (const void *) UI_method_get_reader,
    (const void *) UI_method_get_writer,
    (const void *) UI_method_set_closer,
    (const void *) UI_method_set_data_duplicator,
    (const void *) UI_method_set_ex_data,
    (const void *) UI_method_set_flusher,
    (const void *) UI_method_set_opener,
    (const void *) UI_method_set_prompt_constructor,
    (const void *) UI_method_set_reader,
    (const void *) UI_method_set_writer,
    (const void *) UI_new,
    (const void *) UI_new_method,
    (const void *) UI_null,
    (const void *) UI_process,
    (const void *) UI_set_default_method,
    (const void *) UI_set_ex_data,
    (const void *) UI_set_method,
    (const void *) UI_set_result,
    (const void *) UI_set_result_ex,
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
