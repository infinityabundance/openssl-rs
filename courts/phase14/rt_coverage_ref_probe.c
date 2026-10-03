/*
 * RT-PHASE14-REF -- the reference basis the TLS/DTLS (libssl) stratum requires,
 * and nothing more.
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
 * The 600 names below are the whole of the stratum's atlas-owned universe,
 * `forensics/atlas/symbol-ownership.json`'s `owner_phase == 14` rows: 582 declared
 * in `ssl.h`, 13 in `tls1.h`, 4 in `srtp.h` and 1 in `sslerr_legacy.h`. **Unlike
 * every earlier reference basis, not one of them is implemented at activation**:
 * libssl is the crate's second distribution namespace, its own stratum lands
 * nothing before 14.1, and `forensics/atlas/implemented-surface.json` therefore
 * records `0` implemented `libssl` symbols. The candidate distribution still
 * *defines* every one of the 603 `libssl` exports -- the Phase 2 ABI scaffold
 * (`artifacts/phase2/shell/libssl.shell.rs`) defines them and aborts when one is
 * called -- so the link proves each name exists while claiming nothing about its
 * behaviour. Taking an address rather than calling is what keeps that safe: the
 * scaffolds abort on call, and this probe never calls. The atlas's phase-14 row
 * therefore binds no `referenced` name yet (`implemented: 0`); this basis is
 * registered so the join has a probe for the stratum from the day it begins, and
 * the first name a subphase implements is already imported here.
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
extern void BIO_f_ssl(void);
extern void BIO_new_buffer_ssl_connect(void);
extern void BIO_new_ssl(void);
extern void BIO_new_ssl_connect(void);
extern void BIO_ssl_copy_session_id(void);
extern void BIO_ssl_shutdown(void);
extern void DTLS_client_method(void);
extern void DTLS_get_data_mtu(void);
extern void DTLS_method(void);
extern void DTLS_server_method(void);
extern void DTLS_set_timer_cb(void);
extern void DTLSv1_2_client_method(void);
extern void DTLSv1_2_method(void);
extern void DTLSv1_2_server_method(void);
extern void DTLSv1_client_method(void);
extern void DTLSv1_listen(void);
extern void DTLSv1_method(void);
extern void DTLSv1_server_method(void);
extern void ERR_load_SSL_strings(void);
extern void OPENSSL_cipher_name(void);
extern void OPENSSL_init_ssl(void);
extern void OSSL_default_cipher_list(void);
extern void OSSL_default_ciphersuites(void);
extern void PEM_read_SSL_SESSION(void);
extern void PEM_read_bio_SSL_SESSION(void);
extern void PEM_write_SSL_SESSION(void);
extern void PEM_write_bio_SSL_SESSION(void);
extern void SRP_Calc_A_param(void);
extern void SSL_CIPHER_description(void);
extern void SSL_CIPHER_find(void);
extern void SSL_CIPHER_get_auth_nid(void);
extern void SSL_CIPHER_get_bits(void);
extern void SSL_CIPHER_get_cipher_nid(void);
extern void SSL_CIPHER_get_digest_nid(void);
extern void SSL_CIPHER_get_handshake_digest(void);
extern void SSL_CIPHER_get_id(void);
extern void SSL_CIPHER_get_kx_nid(void);
extern void SSL_CIPHER_get_name(void);
extern void SSL_CIPHER_get_protocol_id(void);
extern void SSL_CIPHER_get_version(void);
extern void SSL_CIPHER_is_aead(void);
extern void SSL_CIPHER_standard_name(void);
extern void SSL_COMP_add_compression_method(void);
extern void SSL_COMP_get0_name(void);
extern void SSL_COMP_get_compression_methods(void);
extern void SSL_COMP_get_id(void);
extern void SSL_COMP_get_name(void);
extern void SSL_COMP_set0_compression_methods(void);
extern void SSL_CONF_CTX_clear_flags(void);
extern void SSL_CONF_CTX_finish(void);
extern void SSL_CONF_CTX_free(void);
extern void SSL_CONF_CTX_new(void);
extern void SSL_CONF_CTX_set1_prefix(void);
extern void SSL_CONF_CTX_set_flags(void);
extern void SSL_CONF_CTX_set_ssl(void);
extern void SSL_CONF_CTX_set_ssl_ctx(void);
extern void SSL_CONF_cmd(void);
extern void SSL_CONF_cmd_argv(void);
extern void SSL_CONF_cmd_value_type(void);
extern void SSL_CTX_SRP_CTX_free(void);
extern void SSL_CTX_SRP_CTX_init(void);
extern void SSL_CTX_add1_to_CA_list(void);
extern void SSL_CTX_add_client_CA(void);
extern void SSL_CTX_add_client_custom_ext(void);
extern void SSL_CTX_add_custom_ext(void);
extern void SSL_CTX_add_server_custom_ext(void);
extern void SSL_CTX_add_session(void);
extern void SSL_CTX_callback_ctrl(void);
extern void SSL_CTX_check_private_key(void);
extern void SSL_CTX_clear_options(void);
extern void SSL_CTX_compress_certs(void);
extern void SSL_CTX_config(void);
extern void SSL_CTX_ct_is_enabled(void);
extern void SSL_CTX_ctrl(void);
extern void SSL_CTX_dane_clear_flags(void);
extern void SSL_CTX_dane_enable(void);
extern void SSL_CTX_dane_mtype_set(void);
extern void SSL_CTX_dane_set_flags(void);
extern void SSL_CTX_enable_ct(void);
extern void SSL_CTX_flush_sessions(void);
extern void SSL_CTX_flush_sessions_ex(void);
extern void SSL_CTX_free(void);
extern void SSL_CTX_get0_CA_list(void);
extern void SSL_CTX_get0_certificate(void);
extern void SSL_CTX_get0_client_cert_type(void);
extern void SSL_CTX_get0_ctlog_store(void);
extern void SSL_CTX_get0_param(void);
extern void SSL_CTX_get0_privatekey(void);
extern void SSL_CTX_get0_security_ex_data(void);
extern void SSL_CTX_get0_server_cert_type(void);
extern void SSL_CTX_get1_compressed_cert(void);
extern void SSL_CTX_get_cert_store(void);
extern void SSL_CTX_get_ciphers(void);
extern void SSL_CTX_get_client_CA_list(void);
extern void SSL_CTX_get_client_cert_cb(void);
extern void SSL_CTX_get_default_passwd_cb(void);
extern void SSL_CTX_get_default_passwd_cb_userdata(void);
extern void SSL_CTX_get_domain_flags(void);
extern void SSL_CTX_get_ex_data(void);
extern void SSL_CTX_get_info_callback(void);
extern void SSL_CTX_get_keylog_callback(void);
extern void SSL_CTX_get_max_early_data(void);
extern void SSL_CTX_get_num_tickets(void);
extern void SSL_CTX_get_options(void);
extern void SSL_CTX_get_quiet_shutdown(void);
extern void SSL_CTX_get_record_padding_callback_arg(void);
extern void SSL_CTX_get_recv_max_early_data(void);
extern void SSL_CTX_get_security_callback(void);
extern void SSL_CTX_get_security_level(void);
extern void SSL_CTX_get_ssl_method(void);
extern void SSL_CTX_get_timeout(void);
extern void SSL_CTX_get_verify_callback(void);
extern void SSL_CTX_get_verify_depth(void);
extern void SSL_CTX_get_verify_mode(void);
extern void SSL_CTX_has_client_custom_ext(void);
extern void SSL_CTX_load_verify_dir(void);
extern void SSL_CTX_load_verify_file(void);
extern void SSL_CTX_load_verify_locations(void);
extern void SSL_CTX_load_verify_store(void);
extern void SSL_CTX_new(void);
extern void SSL_CTX_new_ex(void);
extern void SSL_CTX_remove_session(void);
extern void SSL_CTX_sess_get_get_cb(void);
extern void SSL_CTX_sess_get_new_cb(void);
extern void SSL_CTX_sess_get_remove_cb(void);
extern void SSL_CTX_sess_set_get_cb(void);
extern void SSL_CTX_sess_set_new_cb(void);
extern void SSL_CTX_sess_set_remove_cb(void);
extern void SSL_CTX_sessions(void);
extern void SSL_CTX_set0_CA_list(void);
extern void SSL_CTX_set0_ctlog_store(void);
extern void SSL_CTX_set0_security_ex_data(void);
extern void SSL_CTX_set0_tmp_dh_pkey(void);
extern void SSL_CTX_set1_cert_comp_preference(void);
extern void SSL_CTX_set1_cert_store(void);
extern void SSL_CTX_set1_client_cert_type(void);
extern void SSL_CTX_set1_compressed_cert(void);
extern void SSL_CTX_set1_param(void);
extern void SSL_CTX_set1_server_cert_type(void);
extern void SSL_CTX_set_allow_early_data_cb(void);
extern void SSL_CTX_set_alpn_protos(void);
extern void SSL_CTX_set_alpn_select_cb(void);
extern void SSL_CTX_set_async_callback(void);
extern void SSL_CTX_set_async_callback_arg(void);
extern void SSL_CTX_set_block_padding(void);
extern void SSL_CTX_set_block_padding_ex(void);
extern void SSL_CTX_set_cert_cb(void);
extern void SSL_CTX_set_cert_store(void);
extern void SSL_CTX_set_cert_verify_callback(void);
extern void SSL_CTX_set_cipher_list(void);
extern void SSL_CTX_set_ciphersuites(void);
extern void SSL_CTX_set_client_CA_list(void);
extern void SSL_CTX_set_client_cert_cb(void);
extern void SSL_CTX_set_client_cert_engine(void);
extern void SSL_CTX_set_client_hello_cb(void);
extern void SSL_CTX_set_cookie_generate_cb(void);
extern void SSL_CTX_set_cookie_verify_cb(void);
extern void SSL_CTX_set_ct_validation_callback(void);
extern void SSL_CTX_set_ctlog_list_file(void);
extern void SSL_CTX_set_default_ctlog_list_file(void);
extern void SSL_CTX_set_default_passwd_cb(void);
extern void SSL_CTX_set_default_passwd_cb_userdata(void);
extern void SSL_CTX_set_default_read_buffer_len(void);
extern void SSL_CTX_set_default_verify_dir(void);
extern void SSL_CTX_set_default_verify_file(void);
extern void SSL_CTX_set_default_verify_paths(void);
extern void SSL_CTX_set_default_verify_store(void);
extern void SSL_CTX_set_domain_flags(void);
extern void SSL_CTX_set_ex_data(void);
extern void SSL_CTX_set_generate_session_id(void);
extern void SSL_CTX_set_info_callback(void);
extern void SSL_CTX_set_keylog_callback(void);
extern void SSL_CTX_set_max_early_data(void);
extern void SSL_CTX_set_msg_callback(void);
extern void SSL_CTX_set_new_pending_conn_cb(void);
extern void SSL_CTX_set_next_proto_select_cb(void);
extern void SSL_CTX_set_next_protos_advertised_cb(void);
extern void SSL_CTX_set_not_resumable_session_callback(void);
extern void SSL_CTX_set_num_tickets(void);
extern void SSL_CTX_set_options(void);
extern void SSL_CTX_set_post_handshake_auth(void);
extern void SSL_CTX_set_psk_client_callback(void);
extern void SSL_CTX_set_psk_find_session_callback(void);
extern void SSL_CTX_set_psk_server_callback(void);
extern void SSL_CTX_set_psk_use_session_callback(void);
extern void SSL_CTX_set_purpose(void);
extern void SSL_CTX_set_quiet_shutdown(void);
extern void SSL_CTX_set_record_padding_callback(void);
extern void SSL_CTX_set_record_padding_callback_arg(void);
extern void SSL_CTX_set_recv_max_early_data(void);
extern void SSL_CTX_set_security_callback(void);
extern void SSL_CTX_set_security_level(void);
extern void SSL_CTX_set_session_id_context(void);
extern void SSL_CTX_set_session_ticket_cb(void);
extern void SSL_CTX_set_srp_cb_arg(void);
extern void SSL_CTX_set_srp_client_pwd_callback(void);
extern void SSL_CTX_set_srp_password(void);
extern void SSL_CTX_set_srp_strength(void);
extern void SSL_CTX_set_srp_username(void);
extern void SSL_CTX_set_srp_username_callback(void);
extern void SSL_CTX_set_srp_verify_param_callback(void);
extern void SSL_CTX_set_ssl_version(void);
extern void SSL_CTX_set_stateless_cookie_generate_cb(void);
extern void SSL_CTX_set_stateless_cookie_verify_cb(void);
extern void SSL_CTX_set_timeout(void);
extern void SSL_CTX_set_tlsext_max_fragment_length(void);
extern void SSL_CTX_set_tlsext_ticket_key_evp_cb(void);
extern void SSL_CTX_set_tlsext_use_srtp(void);
extern void SSL_CTX_set_tmp_dh_callback(void);
extern void SSL_CTX_set_trust(void);
extern void SSL_CTX_set_verify(void);
extern void SSL_CTX_set_verify_depth(void);
extern void SSL_CTX_up_ref(void);
extern void SSL_CTX_use_PrivateKey(void);
extern void SSL_CTX_use_PrivateKey_ASN1(void);
extern void SSL_CTX_use_PrivateKey_file(void);
extern void SSL_CTX_use_RSAPrivateKey(void);
extern void SSL_CTX_use_RSAPrivateKey_ASN1(void);
extern void SSL_CTX_use_RSAPrivateKey_file(void);
extern void SSL_CTX_use_cert_and_key(void);
extern void SSL_CTX_use_certificate(void);
extern void SSL_CTX_use_certificate_ASN1(void);
extern void SSL_CTX_use_certificate_chain_file(void);
extern void SSL_CTX_use_certificate_file(void);
extern void SSL_CTX_use_psk_identity_hint(void);
extern void SSL_CTX_use_serverinfo(void);
extern void SSL_CTX_use_serverinfo_ex(void);
extern void SSL_CTX_use_serverinfo_file(void);
extern void SSL_SESSION_dup(void);
extern void SSL_SESSION_free(void);
extern void SSL_SESSION_get0_alpn_selected(void);
extern void SSL_SESSION_get0_cipher(void);
extern void SSL_SESSION_get0_hostname(void);
extern void SSL_SESSION_get0_id_context(void);
extern void SSL_SESSION_get0_peer(void);
extern void SSL_SESSION_get0_peer_rpk(void);
extern void SSL_SESSION_get0_ticket(void);
extern void SSL_SESSION_get0_ticket_appdata(void);
extern void SSL_SESSION_get_compress_id(void);
extern void SSL_SESSION_get_ex_data(void);
extern void SSL_SESSION_get_id(void);
extern void SSL_SESSION_get_master_key(void);
extern void SSL_SESSION_get_max_early_data(void);
extern void SSL_SESSION_get_max_fragment_length(void);
extern void SSL_SESSION_get_protocol_version(void);
extern void SSL_SESSION_get_ticket_lifetime_hint(void);
extern void SSL_SESSION_get_time(void);
extern void SSL_SESSION_get_time_ex(void);
extern void SSL_SESSION_get_timeout(void);
extern void SSL_SESSION_has_ticket(void);
extern void SSL_SESSION_is_resumable(void);
extern void SSL_SESSION_new(void);
extern void SSL_SESSION_print(void);
extern void SSL_SESSION_print_fp(void);
extern void SSL_SESSION_print_keylog(void);
extern void SSL_SESSION_set1_alpn_selected(void);
extern void SSL_SESSION_set1_hostname(void);
extern void SSL_SESSION_set1_id(void);
extern void SSL_SESSION_set1_id_context(void);
extern void SSL_SESSION_set1_master_key(void);
extern void SSL_SESSION_set1_ticket_appdata(void);
extern void SSL_SESSION_set_cipher(void);
extern void SSL_SESSION_set_ex_data(void);
extern void SSL_SESSION_set_max_early_data(void);
extern void SSL_SESSION_set_protocol_version(void);
extern void SSL_SESSION_set_time(void);
extern void SSL_SESSION_set_time_ex(void);
extern void SSL_SESSION_set_timeout(void);
extern void SSL_SESSION_up_ref(void);
extern void SSL_SRP_CTX_free(void);
extern void SSL_SRP_CTX_init(void);
extern void SSL_accept(void);
extern void SSL_accept_connection(void);
extern void SSL_accept_stream(void);
extern void SSL_add1_host(void);
extern void SSL_add1_to_CA_list(void);
extern void SSL_add_client_CA(void);
extern void SSL_add_dir_cert_subjects_to_stack(void);
extern void SSL_add_expected_rpk(void);
extern void SSL_add_file_cert_subjects_to_stack(void);
extern void SSL_add_ssl_module(void);
extern void SSL_add_store_cert_subjects_to_stack(void);
extern void SSL_alert_desc_string(void);
extern void SSL_alert_desc_string_long(void);
extern void SSL_alert_type_string(void);
extern void SSL_alert_type_string_long(void);
extern void SSL_alloc_buffers(void);
extern void SSL_bytes_to_cipher_list(void);
extern void SSL_callback_ctrl(void);
extern void SSL_certs_clear(void);
extern void SSL_check_chain(void);
extern void SSL_check_private_key(void);
extern void SSL_clear(void);
extern void SSL_clear_options(void);
extern void SSL_client_hello_get0_ciphers(void);
extern void SSL_client_hello_get0_compression_methods(void);
extern void SSL_client_hello_get0_ext(void);
extern void SSL_client_hello_get0_legacy_version(void);
extern void SSL_client_hello_get0_random(void);
extern void SSL_client_hello_get0_session_id(void);
extern void SSL_client_hello_get1_extensions_present(void);
extern void SSL_client_hello_get_extension_order(void);
extern void SSL_client_hello_isv2(void);
extern void SSL_client_version(void);
extern void SSL_compress_certs(void);
extern void SSL_config(void);
extern void SSL_connect(void);
extern void SSL_copy_session_id(void);
extern void SSL_ct_is_enabled(void);
extern void SSL_ctrl(void);
extern void SSL_dane_clear_flags(void);
extern void SSL_dane_enable(void);
extern void SSL_dane_set_flags(void);
extern void SSL_dane_tlsa_add(void);
extern void SSL_do_handshake(void);
extern void SSL_dup(void);
extern void SSL_dup_CA_list(void);
extern void SSL_enable_ct(void);
extern void SSL_export_keying_material(void);
extern void SSL_export_keying_material_early(void);
extern void SSL_extension_supported(void);
extern void SSL_free(void);
extern void SSL_free_buffers(void);
extern void SSL_get0_CA_list(void);
extern void SSL_get0_alpn_selected(void);
extern void SSL_get0_client_cert_type(void);
extern void SSL_get0_connection(void);
extern void SSL_get0_dane(void);
extern void SSL_get0_dane_authority(void);
extern void SSL_get0_dane_tlsa(void);
extern void SSL_get0_domain(void);
extern void SSL_get0_group_name(void);
extern void SSL_get0_listener(void);
extern void SSL_get0_next_proto_negotiated(void);
extern void SSL_get0_param(void);
extern void SSL_get0_peer_CA_list(void);
extern void SSL_get0_peer_certificate(void);
extern void SSL_get0_peer_rpk(void);
extern void SSL_get0_peer_scts(void);
extern void SSL_get0_peername(void);
extern void SSL_get0_security_ex_data(void);
extern void SSL_get0_server_cert_type(void);
extern void SSL_get0_verified_chain(void);
extern void SSL_get1_builtin_sigalgs(void);
extern void SSL_get1_compressed_cert(void);
extern void SSL_get1_peer_certificate(void);
extern void SSL_get1_session(void);
extern void SSL_get1_supported_ciphers(void);
extern void SSL_get_SSL_CTX(void);
extern void SSL_get_accept_connection_queue_len(void);
extern void SSL_get_accept_stream_queue_len(void);
extern void SSL_get_all_async_fds(void);
extern void SSL_get_async_status(void);
extern void SSL_get_blocking_mode(void);
extern void SSL_get_certificate(void);
extern void SSL_get_changed_async_fds(void);
extern void SSL_get_cipher_list(void);
extern void SSL_get_ciphers(void);
extern void SSL_get_client_CA_list(void);
extern void SSL_get_client_ciphers(void);
extern void SSL_get_client_random(void);
extern void SSL_get_conn_close_info(void);
extern void SSL_get_current_cipher(void);
extern void SSL_get_current_compression(void);
extern void SSL_get_current_expansion(void);
extern void SSL_get_default_passwd_cb(void);
extern void SSL_get_default_passwd_cb_userdata(void);
extern void SSL_get_default_timeout(void);
extern void SSL_get_domain_flags(void);
extern void SSL_get_early_data_status(void);
extern void SSL_get_error(void);
extern void SSL_get_event_timeout(void);
extern void SSL_get_ex_data(void);
extern void SSL_get_ex_data_X509_STORE_CTX_idx(void);
extern void SSL_get_fd(void);
extern void SSL_get_finished(void);
extern void SSL_get_handshake_rtt(void);
extern void SSL_get_info_callback(void);
extern void SSL_get_key_update_type(void);
extern void SSL_get_max_early_data(void);
extern void SSL_get_negotiated_client_cert_type(void);
extern void SSL_get_negotiated_server_cert_type(void);
extern void SSL_get_num_tickets(void);
extern void SSL_get_options(void);
extern void SSL_get_peer_cert_chain(void);
extern void SSL_get_peer_finished(void);
extern void SSL_get_peer_signature_type_nid(void);
extern void SSL_get_pending_cipher(void);
extern void SSL_get_privatekey(void);
extern void SSL_get_psk_identity(void);
extern void SSL_get_psk_identity_hint(void);
extern void SSL_get_quiet_shutdown(void);
extern void SSL_get_rbio(void);
extern void SSL_get_read_ahead(void);
extern void SSL_get_record_padding_callback_arg(void);
extern void SSL_get_recv_max_early_data(void);
extern void SSL_get_rfd(void);
extern void SSL_get_rpoll_descriptor(void);
extern void SSL_get_security_callback(void);
extern void SSL_get_security_level(void);
extern void SSL_get_selected_srtp_profile(void);
extern void SSL_get_server_random(void);
extern void SSL_get_servername(void);
extern void SSL_get_servername_type(void);
extern void SSL_get_session(void);
extern void SSL_get_shared_ciphers(void);
extern void SSL_get_shared_sigalgs(void);
extern void SSL_get_shutdown(void);
extern void SSL_get_sigalgs(void);
extern void SSL_get_signature_type_nid(void);
extern void SSL_get_srp_N(void);
extern void SSL_get_srp_g(void);
extern void SSL_get_srp_userinfo(void);
extern void SSL_get_srp_username(void);
extern void SSL_get_srtp_profiles(void);
extern void SSL_get_ssl_method(void);
extern void SSL_get_state(void);
extern void SSL_get_stream_id(void);
extern void SSL_get_stream_read_error_code(void);
extern void SSL_get_stream_read_state(void);
extern void SSL_get_stream_type(void);
extern void SSL_get_stream_write_error_code(void);
extern void SSL_get_stream_write_state(void);
extern void SSL_get_value_uint(void);
extern void SSL_get_verify_callback(void);
extern void SSL_get_verify_depth(void);
extern void SSL_get_verify_mode(void);
extern void SSL_get_verify_result(void);
extern void SSL_get_version(void);
extern void SSL_get_wbio(void);
extern void SSL_get_wfd(void);
extern void SSL_get_wpoll_descriptor(void);
extern void SSL_group_to_name(void);
extern void SSL_handle_events(void);
extern void SSL_has_matching_session_id(void);
extern void SSL_has_pending(void);
extern void SSL_in_before(void);
extern void SSL_in_init(void);
extern void SSL_inject_net_dgram(void);
extern void SSL_is_connection(void);
extern void SSL_is_domain(void);
extern void SSL_is_dtls(void);
extern void SSL_is_init_finished(void);
extern void SSL_is_listener(void);
extern void SSL_is_quic(void);
extern void SSL_is_server(void);
extern void SSL_is_stream_local(void);
extern void SSL_is_tls(void);
extern void SSL_key_update(void);
extern void SSL_listen(void);
extern void SSL_load_client_CA_file(void);
extern void SSL_load_client_CA_file_ex(void);
extern void SSL_net_read_desired(void);
extern void SSL_net_write_desired(void);
extern void SSL_new(void);
extern void SSL_new_domain(void);
extern void SSL_new_from_listener(void);
extern void SSL_new_listener(void);
extern void SSL_new_listener_from(void);
extern void SSL_new_session_ticket(void);
extern void SSL_new_stream(void);
extern void SSL_peek(void);
extern void SSL_peek_ex(void);
extern void SSL_pending(void);
extern void SSL_poll(void);
extern void SSL_read(void);
extern void SSL_read_early_data(void);
extern void SSL_read_ex(void);
extern void SSL_renegotiate(void);
extern void SSL_renegotiate_abbreviated(void);
extern void SSL_renegotiate_pending(void);
extern void SSL_rstate_string(void);
extern void SSL_rstate_string_long(void);
extern void SSL_select_next_proto(void);
extern void SSL_sendfile(void);
extern void SSL_session_reused(void);
extern void SSL_set0_CA_list(void);
extern void SSL_set0_rbio(void);
extern void SSL_set0_security_ex_data(void);
extern void SSL_set0_tmp_dh_pkey(void);
extern void SSL_set0_wbio(void);
extern void SSL_set1_cert_comp_preference(void);
extern void SSL_set1_client_cert_type(void);
extern void SSL_set1_compressed_cert(void);
extern void SSL_set1_host(void);
extern void SSL_set1_initial_peer_addr(void);
extern void SSL_set1_param(void);
extern void SSL_set1_server_cert_type(void);
extern void SSL_set_SSL_CTX(void);
extern void SSL_set_accept_state(void);
extern void SSL_set_allow_early_data_cb(void);
extern void SSL_set_alpn_protos(void);
extern void SSL_set_async_callback(void);
extern void SSL_set_async_callback_arg(void);
extern void SSL_set_bio(void);
extern void SSL_set_block_padding(void);
extern void SSL_set_block_padding_ex(void);
extern void SSL_set_blocking_mode(void);
extern void SSL_set_cert_cb(void);
extern void SSL_set_cipher_list(void);
extern void SSL_set_ciphersuites(void);
extern void SSL_set_client_CA_list(void);
extern void SSL_set_connect_state(void);
extern void SSL_set_ct_validation_callback(void);
extern void SSL_set_debug(void);
extern void SSL_set_default_passwd_cb(void);
extern void SSL_set_default_passwd_cb_userdata(void);
extern void SSL_set_default_read_buffer_len(void);
extern void SSL_set_default_stream_mode(void);
extern void SSL_set_ex_data(void);
extern void SSL_set_fd(void);
extern void SSL_set_generate_session_id(void);
extern void SSL_set_hostflags(void);
extern void SSL_set_incoming_stream_policy(void);
extern void SSL_set_info_callback(void);
extern void SSL_set_max_early_data(void);
extern void SSL_set_msg_callback(void);
extern void SSL_set_not_resumable_session_callback(void);
extern void SSL_set_num_tickets(void);
extern void SSL_set_options(void);
extern void SSL_set_post_handshake_auth(void);
extern void SSL_set_psk_client_callback(void);
extern void SSL_set_psk_find_session_callback(void);
extern void SSL_set_psk_server_callback(void);
extern void SSL_set_psk_use_session_callback(void);
extern void SSL_set_purpose(void);
extern void SSL_set_quic_tls_cbs(void);
extern void SSL_set_quic_tls_early_data_enabled(void);
extern void SSL_set_quic_tls_transport_params(void);
extern void SSL_set_quiet_shutdown(void);
extern void SSL_set_read_ahead(void);
extern void SSL_set_record_padding_callback(void);
extern void SSL_set_record_padding_callback_arg(void);
extern void SSL_set_recv_max_early_data(void);
extern void SSL_set_rfd(void);
extern void SSL_set_security_callback(void);
extern void SSL_set_security_level(void);
extern void SSL_set_session(void);
extern void SSL_set_session_id_context(void);
extern void SSL_set_session_secret_cb(void);
extern void SSL_set_session_ticket_ext(void);
extern void SSL_set_session_ticket_ext_cb(void);
extern void SSL_set_shutdown(void);
extern void SSL_set_srp_server_param(void);
extern void SSL_set_srp_server_param_pw(void);
extern void SSL_set_ssl_method(void);
extern void SSL_set_tlsext_max_fragment_length(void);
extern void SSL_set_tlsext_use_srtp(void);
extern void SSL_set_tmp_dh_callback(void);
extern void SSL_set_trust(void);
extern void SSL_set_value_uint(void);
extern void SSL_set_verify(void);
extern void SSL_set_verify_depth(void);
extern void SSL_set_verify_result(void);
extern void SSL_set_wfd(void);
extern void SSL_shutdown(void);
extern void SSL_shutdown_ex(void);
extern void SSL_srp_server_param_with_username(void);
extern void SSL_state_string(void);
extern void SSL_state_string_long(void);
extern void SSL_stateless(void);
extern void SSL_stream_conclude(void);
extern void SSL_stream_reset(void);
extern void SSL_trace(void);
extern void SSL_up_ref(void);
extern void SSL_use_PrivateKey(void);
extern void SSL_use_PrivateKey_ASN1(void);
extern void SSL_use_PrivateKey_file(void);
extern void SSL_use_RSAPrivateKey(void);
extern void SSL_use_RSAPrivateKey_ASN1(void);
extern void SSL_use_RSAPrivateKey_file(void);
extern void SSL_use_cert_and_key(void);
extern void SSL_use_certificate(void);
extern void SSL_use_certificate_ASN1(void);
extern void SSL_use_certificate_chain_file(void);
extern void SSL_use_certificate_file(void);
extern void SSL_use_psk_identity_hint(void);
extern void SSL_verify_client_post_handshake(void);
extern void SSL_version(void);
extern void SSL_waiting_for_async(void);
extern void SSL_want(void);
extern void SSL_write(void);
extern void SSL_write_early_data(void);
extern void SSL_write_ex(void);
extern void SSL_write_ex2(void);
extern void TLS_client_method(void);
extern void TLS_method(void);
extern void TLS_server_method(void);
extern void TLSv1_1_client_method(void);
extern void TLSv1_1_method(void);
extern void TLSv1_1_server_method(void);
extern void TLSv1_2_client_method(void);
extern void TLSv1_2_method(void);
extern void TLSv1_2_server_method(void);
extern void TLSv1_client_method(void);
extern void TLSv1_method(void);
extern void TLSv1_server_method(void);
extern void d2i_SSL_SESSION(void);
extern void d2i_SSL_SESSION_ex(void);
extern void i2d_SSL_SESSION(void);

static const void *volatile refs[] = {
    (const void *) BIO_f_ssl,
    (const void *) BIO_new_buffer_ssl_connect,
    (const void *) BIO_new_ssl,
    (const void *) BIO_new_ssl_connect,
    (const void *) BIO_ssl_copy_session_id,
    (const void *) BIO_ssl_shutdown,
    (const void *) DTLS_client_method,
    (const void *) DTLS_get_data_mtu,
    (const void *) DTLS_method,
    (const void *) DTLS_server_method,
    (const void *) DTLS_set_timer_cb,
    (const void *) DTLSv1_2_client_method,
    (const void *) DTLSv1_2_method,
    (const void *) DTLSv1_2_server_method,
    (const void *) DTLSv1_client_method,
    (const void *) DTLSv1_listen,
    (const void *) DTLSv1_method,
    (const void *) DTLSv1_server_method,
    (const void *) ERR_load_SSL_strings,
    (const void *) OPENSSL_cipher_name,
    (const void *) OPENSSL_init_ssl,
    (const void *) OSSL_default_cipher_list,
    (const void *) OSSL_default_ciphersuites,
    (const void *) PEM_read_SSL_SESSION,
    (const void *) PEM_read_bio_SSL_SESSION,
    (const void *) PEM_write_SSL_SESSION,
    (const void *) PEM_write_bio_SSL_SESSION,
    (const void *) SRP_Calc_A_param,
    (const void *) SSL_CIPHER_description,
    (const void *) SSL_CIPHER_find,
    (const void *) SSL_CIPHER_get_auth_nid,
    (const void *) SSL_CIPHER_get_bits,
    (const void *) SSL_CIPHER_get_cipher_nid,
    (const void *) SSL_CIPHER_get_digest_nid,
    (const void *) SSL_CIPHER_get_handshake_digest,
    (const void *) SSL_CIPHER_get_id,
    (const void *) SSL_CIPHER_get_kx_nid,
    (const void *) SSL_CIPHER_get_name,
    (const void *) SSL_CIPHER_get_protocol_id,
    (const void *) SSL_CIPHER_get_version,
    (const void *) SSL_CIPHER_is_aead,
    (const void *) SSL_CIPHER_standard_name,
    (const void *) SSL_COMP_add_compression_method,
    (const void *) SSL_COMP_get0_name,
    (const void *) SSL_COMP_get_compression_methods,
    (const void *) SSL_COMP_get_id,
    (const void *) SSL_COMP_get_name,
    (const void *) SSL_COMP_set0_compression_methods,
    (const void *) SSL_CONF_CTX_clear_flags,
    (const void *) SSL_CONF_CTX_finish,
    (const void *) SSL_CONF_CTX_free,
    (const void *) SSL_CONF_CTX_new,
    (const void *) SSL_CONF_CTX_set1_prefix,
    (const void *) SSL_CONF_CTX_set_flags,
    (const void *) SSL_CONF_CTX_set_ssl,
    (const void *) SSL_CONF_CTX_set_ssl_ctx,
    (const void *) SSL_CONF_cmd,
    (const void *) SSL_CONF_cmd_argv,
    (const void *) SSL_CONF_cmd_value_type,
    (const void *) SSL_CTX_SRP_CTX_free,
    (const void *) SSL_CTX_SRP_CTX_init,
    (const void *) SSL_CTX_add1_to_CA_list,
    (const void *) SSL_CTX_add_client_CA,
    (const void *) SSL_CTX_add_client_custom_ext,
    (const void *) SSL_CTX_add_custom_ext,
    (const void *) SSL_CTX_add_server_custom_ext,
    (const void *) SSL_CTX_add_session,
    (const void *) SSL_CTX_callback_ctrl,
    (const void *) SSL_CTX_check_private_key,
    (const void *) SSL_CTX_clear_options,
    (const void *) SSL_CTX_compress_certs,
    (const void *) SSL_CTX_config,
    (const void *) SSL_CTX_ct_is_enabled,
    (const void *) SSL_CTX_ctrl,
    (const void *) SSL_CTX_dane_clear_flags,
    (const void *) SSL_CTX_dane_enable,
    (const void *) SSL_CTX_dane_mtype_set,
    (const void *) SSL_CTX_dane_set_flags,
    (const void *) SSL_CTX_enable_ct,
    (const void *) SSL_CTX_flush_sessions,
    (const void *) SSL_CTX_flush_sessions_ex,
    (const void *) SSL_CTX_free,
    (const void *) SSL_CTX_get0_CA_list,
    (const void *) SSL_CTX_get0_certificate,
    (const void *) SSL_CTX_get0_client_cert_type,
    (const void *) SSL_CTX_get0_ctlog_store,
    (const void *) SSL_CTX_get0_param,
    (const void *) SSL_CTX_get0_privatekey,
    (const void *) SSL_CTX_get0_security_ex_data,
    (const void *) SSL_CTX_get0_server_cert_type,
    (const void *) SSL_CTX_get1_compressed_cert,
    (const void *) SSL_CTX_get_cert_store,
    (const void *) SSL_CTX_get_ciphers,
    (const void *) SSL_CTX_get_client_CA_list,
    (const void *) SSL_CTX_get_client_cert_cb,
    (const void *) SSL_CTX_get_default_passwd_cb,
    (const void *) SSL_CTX_get_default_passwd_cb_userdata,
    (const void *) SSL_CTX_get_domain_flags,
    (const void *) SSL_CTX_get_ex_data,
    (const void *) SSL_CTX_get_info_callback,
    (const void *) SSL_CTX_get_keylog_callback,
    (const void *) SSL_CTX_get_max_early_data,
    (const void *) SSL_CTX_get_num_tickets,
    (const void *) SSL_CTX_get_options,
    (const void *) SSL_CTX_get_quiet_shutdown,
    (const void *) SSL_CTX_get_record_padding_callback_arg,
    (const void *) SSL_CTX_get_recv_max_early_data,
    (const void *) SSL_CTX_get_security_callback,
    (const void *) SSL_CTX_get_security_level,
    (const void *) SSL_CTX_get_ssl_method,
    (const void *) SSL_CTX_get_timeout,
    (const void *) SSL_CTX_get_verify_callback,
    (const void *) SSL_CTX_get_verify_depth,
    (const void *) SSL_CTX_get_verify_mode,
    (const void *) SSL_CTX_has_client_custom_ext,
    (const void *) SSL_CTX_load_verify_dir,
    (const void *) SSL_CTX_load_verify_file,
    (const void *) SSL_CTX_load_verify_locations,
    (const void *) SSL_CTX_load_verify_store,
    (const void *) SSL_CTX_new,
    (const void *) SSL_CTX_new_ex,
    (const void *) SSL_CTX_remove_session,
    (const void *) SSL_CTX_sess_get_get_cb,
    (const void *) SSL_CTX_sess_get_new_cb,
    (const void *) SSL_CTX_sess_get_remove_cb,
    (const void *) SSL_CTX_sess_set_get_cb,
    (const void *) SSL_CTX_sess_set_new_cb,
    (const void *) SSL_CTX_sess_set_remove_cb,
    (const void *) SSL_CTX_sessions,
    (const void *) SSL_CTX_set0_CA_list,
    (const void *) SSL_CTX_set0_ctlog_store,
    (const void *) SSL_CTX_set0_security_ex_data,
    (const void *) SSL_CTX_set0_tmp_dh_pkey,
    (const void *) SSL_CTX_set1_cert_comp_preference,
    (const void *) SSL_CTX_set1_cert_store,
    (const void *) SSL_CTX_set1_client_cert_type,
    (const void *) SSL_CTX_set1_compressed_cert,
    (const void *) SSL_CTX_set1_param,
    (const void *) SSL_CTX_set1_server_cert_type,
    (const void *) SSL_CTX_set_allow_early_data_cb,
    (const void *) SSL_CTX_set_alpn_protos,
    (const void *) SSL_CTX_set_alpn_select_cb,
    (const void *) SSL_CTX_set_async_callback,
    (const void *) SSL_CTX_set_async_callback_arg,
    (const void *) SSL_CTX_set_block_padding,
    (const void *) SSL_CTX_set_block_padding_ex,
    (const void *) SSL_CTX_set_cert_cb,
    (const void *) SSL_CTX_set_cert_store,
    (const void *) SSL_CTX_set_cert_verify_callback,
    (const void *) SSL_CTX_set_cipher_list,
    (const void *) SSL_CTX_set_ciphersuites,
    (const void *) SSL_CTX_set_client_CA_list,
    (const void *) SSL_CTX_set_client_cert_cb,
    (const void *) SSL_CTX_set_client_cert_engine,
    (const void *) SSL_CTX_set_client_hello_cb,
    (const void *) SSL_CTX_set_cookie_generate_cb,
    (const void *) SSL_CTX_set_cookie_verify_cb,
    (const void *) SSL_CTX_set_ct_validation_callback,
    (const void *) SSL_CTX_set_ctlog_list_file,
    (const void *) SSL_CTX_set_default_ctlog_list_file,
    (const void *) SSL_CTX_set_default_passwd_cb,
    (const void *) SSL_CTX_set_default_passwd_cb_userdata,
    (const void *) SSL_CTX_set_default_read_buffer_len,
    (const void *) SSL_CTX_set_default_verify_dir,
    (const void *) SSL_CTX_set_default_verify_file,
    (const void *) SSL_CTX_set_default_verify_paths,
    (const void *) SSL_CTX_set_default_verify_store,
    (const void *) SSL_CTX_set_domain_flags,
    (const void *) SSL_CTX_set_ex_data,
    (const void *) SSL_CTX_set_generate_session_id,
    (const void *) SSL_CTX_set_info_callback,
    (const void *) SSL_CTX_set_keylog_callback,
    (const void *) SSL_CTX_set_max_early_data,
    (const void *) SSL_CTX_set_msg_callback,
    (const void *) SSL_CTX_set_new_pending_conn_cb,
    (const void *) SSL_CTX_set_next_proto_select_cb,
    (const void *) SSL_CTX_set_next_protos_advertised_cb,
    (const void *) SSL_CTX_set_not_resumable_session_callback,
    (const void *) SSL_CTX_set_num_tickets,
    (const void *) SSL_CTX_set_options,
    (const void *) SSL_CTX_set_post_handshake_auth,
    (const void *) SSL_CTX_set_psk_client_callback,
    (const void *) SSL_CTX_set_psk_find_session_callback,
    (const void *) SSL_CTX_set_psk_server_callback,
    (const void *) SSL_CTX_set_psk_use_session_callback,
    (const void *) SSL_CTX_set_purpose,
    (const void *) SSL_CTX_set_quiet_shutdown,
    (const void *) SSL_CTX_set_record_padding_callback,
    (const void *) SSL_CTX_set_record_padding_callback_arg,
    (const void *) SSL_CTX_set_recv_max_early_data,
    (const void *) SSL_CTX_set_security_callback,
    (const void *) SSL_CTX_set_security_level,
    (const void *) SSL_CTX_set_session_id_context,
    (const void *) SSL_CTX_set_session_ticket_cb,
    (const void *) SSL_CTX_set_srp_cb_arg,
    (const void *) SSL_CTX_set_srp_client_pwd_callback,
    (const void *) SSL_CTX_set_srp_password,
    (const void *) SSL_CTX_set_srp_strength,
    (const void *) SSL_CTX_set_srp_username,
    (const void *) SSL_CTX_set_srp_username_callback,
    (const void *) SSL_CTX_set_srp_verify_param_callback,
    (const void *) SSL_CTX_set_ssl_version,
    (const void *) SSL_CTX_set_stateless_cookie_generate_cb,
    (const void *) SSL_CTX_set_stateless_cookie_verify_cb,
    (const void *) SSL_CTX_set_timeout,
    (const void *) SSL_CTX_set_tlsext_max_fragment_length,
    (const void *) SSL_CTX_set_tlsext_ticket_key_evp_cb,
    (const void *) SSL_CTX_set_tlsext_use_srtp,
    (const void *) SSL_CTX_set_tmp_dh_callback,
    (const void *) SSL_CTX_set_trust,
    (const void *) SSL_CTX_set_verify,
    (const void *) SSL_CTX_set_verify_depth,
    (const void *) SSL_CTX_up_ref,
    (const void *) SSL_CTX_use_PrivateKey,
    (const void *) SSL_CTX_use_PrivateKey_ASN1,
    (const void *) SSL_CTX_use_PrivateKey_file,
    (const void *) SSL_CTX_use_RSAPrivateKey,
    (const void *) SSL_CTX_use_RSAPrivateKey_ASN1,
    (const void *) SSL_CTX_use_RSAPrivateKey_file,
    (const void *) SSL_CTX_use_cert_and_key,
    (const void *) SSL_CTX_use_certificate,
    (const void *) SSL_CTX_use_certificate_ASN1,
    (const void *) SSL_CTX_use_certificate_chain_file,
    (const void *) SSL_CTX_use_certificate_file,
    (const void *) SSL_CTX_use_psk_identity_hint,
    (const void *) SSL_CTX_use_serverinfo,
    (const void *) SSL_CTX_use_serverinfo_ex,
    (const void *) SSL_CTX_use_serverinfo_file,
    (const void *) SSL_SESSION_dup,
    (const void *) SSL_SESSION_free,
    (const void *) SSL_SESSION_get0_alpn_selected,
    (const void *) SSL_SESSION_get0_cipher,
    (const void *) SSL_SESSION_get0_hostname,
    (const void *) SSL_SESSION_get0_id_context,
    (const void *) SSL_SESSION_get0_peer,
    (const void *) SSL_SESSION_get0_peer_rpk,
    (const void *) SSL_SESSION_get0_ticket,
    (const void *) SSL_SESSION_get0_ticket_appdata,
    (const void *) SSL_SESSION_get_compress_id,
    (const void *) SSL_SESSION_get_ex_data,
    (const void *) SSL_SESSION_get_id,
    (const void *) SSL_SESSION_get_master_key,
    (const void *) SSL_SESSION_get_max_early_data,
    (const void *) SSL_SESSION_get_max_fragment_length,
    (const void *) SSL_SESSION_get_protocol_version,
    (const void *) SSL_SESSION_get_ticket_lifetime_hint,
    (const void *) SSL_SESSION_get_time,
    (const void *) SSL_SESSION_get_time_ex,
    (const void *) SSL_SESSION_get_timeout,
    (const void *) SSL_SESSION_has_ticket,
    (const void *) SSL_SESSION_is_resumable,
    (const void *) SSL_SESSION_new,
    (const void *) SSL_SESSION_print,
    (const void *) SSL_SESSION_print_fp,
    (const void *) SSL_SESSION_print_keylog,
    (const void *) SSL_SESSION_set1_alpn_selected,
    (const void *) SSL_SESSION_set1_hostname,
    (const void *) SSL_SESSION_set1_id,
    (const void *) SSL_SESSION_set1_id_context,
    (const void *) SSL_SESSION_set1_master_key,
    (const void *) SSL_SESSION_set1_ticket_appdata,
    (const void *) SSL_SESSION_set_cipher,
    (const void *) SSL_SESSION_set_ex_data,
    (const void *) SSL_SESSION_set_max_early_data,
    (const void *) SSL_SESSION_set_protocol_version,
    (const void *) SSL_SESSION_set_time,
    (const void *) SSL_SESSION_set_time_ex,
    (const void *) SSL_SESSION_set_timeout,
    (const void *) SSL_SESSION_up_ref,
    (const void *) SSL_SRP_CTX_free,
    (const void *) SSL_SRP_CTX_init,
    (const void *) SSL_accept,
    (const void *) SSL_accept_connection,
    (const void *) SSL_accept_stream,
    (const void *) SSL_add1_host,
    (const void *) SSL_add1_to_CA_list,
    (const void *) SSL_add_client_CA,
    (const void *) SSL_add_dir_cert_subjects_to_stack,
    (const void *) SSL_add_expected_rpk,
    (const void *) SSL_add_file_cert_subjects_to_stack,
    (const void *) SSL_add_ssl_module,
    (const void *) SSL_add_store_cert_subjects_to_stack,
    (const void *) SSL_alert_desc_string,
    (const void *) SSL_alert_desc_string_long,
    (const void *) SSL_alert_type_string,
    (const void *) SSL_alert_type_string_long,
    (const void *) SSL_alloc_buffers,
    (const void *) SSL_bytes_to_cipher_list,
    (const void *) SSL_callback_ctrl,
    (const void *) SSL_certs_clear,
    (const void *) SSL_check_chain,
    (const void *) SSL_check_private_key,
    (const void *) SSL_clear,
    (const void *) SSL_clear_options,
    (const void *) SSL_client_hello_get0_ciphers,
    (const void *) SSL_client_hello_get0_compression_methods,
    (const void *) SSL_client_hello_get0_ext,
    (const void *) SSL_client_hello_get0_legacy_version,
    (const void *) SSL_client_hello_get0_random,
    (const void *) SSL_client_hello_get0_session_id,
    (const void *) SSL_client_hello_get1_extensions_present,
    (const void *) SSL_client_hello_get_extension_order,
    (const void *) SSL_client_hello_isv2,
    (const void *) SSL_client_version,
    (const void *) SSL_compress_certs,
    (const void *) SSL_config,
    (const void *) SSL_connect,
    (const void *) SSL_copy_session_id,
    (const void *) SSL_ct_is_enabled,
    (const void *) SSL_ctrl,
    (const void *) SSL_dane_clear_flags,
    (const void *) SSL_dane_enable,
    (const void *) SSL_dane_set_flags,
    (const void *) SSL_dane_tlsa_add,
    (const void *) SSL_do_handshake,
    (const void *) SSL_dup,
    (const void *) SSL_dup_CA_list,
    (const void *) SSL_enable_ct,
    (const void *) SSL_export_keying_material,
    (const void *) SSL_export_keying_material_early,
    (const void *) SSL_extension_supported,
    (const void *) SSL_free,
    (const void *) SSL_free_buffers,
    (const void *) SSL_get0_CA_list,
    (const void *) SSL_get0_alpn_selected,
    (const void *) SSL_get0_client_cert_type,
    (const void *) SSL_get0_connection,
    (const void *) SSL_get0_dane,
    (const void *) SSL_get0_dane_authority,
    (const void *) SSL_get0_dane_tlsa,
    (const void *) SSL_get0_domain,
    (const void *) SSL_get0_group_name,
    (const void *) SSL_get0_listener,
    (const void *) SSL_get0_next_proto_negotiated,
    (const void *) SSL_get0_param,
    (const void *) SSL_get0_peer_CA_list,
    (const void *) SSL_get0_peer_certificate,
    (const void *) SSL_get0_peer_rpk,
    (const void *) SSL_get0_peer_scts,
    (const void *) SSL_get0_peername,
    (const void *) SSL_get0_security_ex_data,
    (const void *) SSL_get0_server_cert_type,
    (const void *) SSL_get0_verified_chain,
    (const void *) SSL_get1_builtin_sigalgs,
    (const void *) SSL_get1_compressed_cert,
    (const void *) SSL_get1_peer_certificate,
    (const void *) SSL_get1_session,
    (const void *) SSL_get1_supported_ciphers,
    (const void *) SSL_get_SSL_CTX,
    (const void *) SSL_get_accept_connection_queue_len,
    (const void *) SSL_get_accept_stream_queue_len,
    (const void *) SSL_get_all_async_fds,
    (const void *) SSL_get_async_status,
    (const void *) SSL_get_blocking_mode,
    (const void *) SSL_get_certificate,
    (const void *) SSL_get_changed_async_fds,
    (const void *) SSL_get_cipher_list,
    (const void *) SSL_get_ciphers,
    (const void *) SSL_get_client_CA_list,
    (const void *) SSL_get_client_ciphers,
    (const void *) SSL_get_client_random,
    (const void *) SSL_get_conn_close_info,
    (const void *) SSL_get_current_cipher,
    (const void *) SSL_get_current_compression,
    (const void *) SSL_get_current_expansion,
    (const void *) SSL_get_default_passwd_cb,
    (const void *) SSL_get_default_passwd_cb_userdata,
    (const void *) SSL_get_default_timeout,
    (const void *) SSL_get_domain_flags,
    (const void *) SSL_get_early_data_status,
    (const void *) SSL_get_error,
    (const void *) SSL_get_event_timeout,
    (const void *) SSL_get_ex_data,
    (const void *) SSL_get_ex_data_X509_STORE_CTX_idx,
    (const void *) SSL_get_fd,
    (const void *) SSL_get_finished,
    (const void *) SSL_get_handshake_rtt,
    (const void *) SSL_get_info_callback,
    (const void *) SSL_get_key_update_type,
    (const void *) SSL_get_max_early_data,
    (const void *) SSL_get_negotiated_client_cert_type,
    (const void *) SSL_get_negotiated_server_cert_type,
    (const void *) SSL_get_num_tickets,
    (const void *) SSL_get_options,
    (const void *) SSL_get_peer_cert_chain,
    (const void *) SSL_get_peer_finished,
    (const void *) SSL_get_peer_signature_type_nid,
    (const void *) SSL_get_pending_cipher,
    (const void *) SSL_get_privatekey,
    (const void *) SSL_get_psk_identity,
    (const void *) SSL_get_psk_identity_hint,
    (const void *) SSL_get_quiet_shutdown,
    (const void *) SSL_get_rbio,
    (const void *) SSL_get_read_ahead,
    (const void *) SSL_get_record_padding_callback_arg,
    (const void *) SSL_get_recv_max_early_data,
    (const void *) SSL_get_rfd,
    (const void *) SSL_get_rpoll_descriptor,
    (const void *) SSL_get_security_callback,
    (const void *) SSL_get_security_level,
    (const void *) SSL_get_selected_srtp_profile,
    (const void *) SSL_get_server_random,
    (const void *) SSL_get_servername,
    (const void *) SSL_get_servername_type,
    (const void *) SSL_get_session,
    (const void *) SSL_get_shared_ciphers,
    (const void *) SSL_get_shared_sigalgs,
    (const void *) SSL_get_shutdown,
    (const void *) SSL_get_sigalgs,
    (const void *) SSL_get_signature_type_nid,
    (const void *) SSL_get_srp_N,
    (const void *) SSL_get_srp_g,
    (const void *) SSL_get_srp_userinfo,
    (const void *) SSL_get_srp_username,
    (const void *) SSL_get_srtp_profiles,
    (const void *) SSL_get_ssl_method,
    (const void *) SSL_get_state,
    (const void *) SSL_get_stream_id,
    (const void *) SSL_get_stream_read_error_code,
    (const void *) SSL_get_stream_read_state,
    (const void *) SSL_get_stream_type,
    (const void *) SSL_get_stream_write_error_code,
    (const void *) SSL_get_stream_write_state,
    (const void *) SSL_get_value_uint,
    (const void *) SSL_get_verify_callback,
    (const void *) SSL_get_verify_depth,
    (const void *) SSL_get_verify_mode,
    (const void *) SSL_get_verify_result,
    (const void *) SSL_get_version,
    (const void *) SSL_get_wbio,
    (const void *) SSL_get_wfd,
    (const void *) SSL_get_wpoll_descriptor,
    (const void *) SSL_group_to_name,
    (const void *) SSL_handle_events,
    (const void *) SSL_has_matching_session_id,
    (const void *) SSL_has_pending,
    (const void *) SSL_in_before,
    (const void *) SSL_in_init,
    (const void *) SSL_inject_net_dgram,
    (const void *) SSL_is_connection,
    (const void *) SSL_is_domain,
    (const void *) SSL_is_dtls,
    (const void *) SSL_is_init_finished,
    (const void *) SSL_is_listener,
    (const void *) SSL_is_quic,
    (const void *) SSL_is_server,
    (const void *) SSL_is_stream_local,
    (const void *) SSL_is_tls,
    (const void *) SSL_key_update,
    (const void *) SSL_listen,
    (const void *) SSL_load_client_CA_file,
    (const void *) SSL_load_client_CA_file_ex,
    (const void *) SSL_net_read_desired,
    (const void *) SSL_net_write_desired,
    (const void *) SSL_new,
    (const void *) SSL_new_domain,
    (const void *) SSL_new_from_listener,
    (const void *) SSL_new_listener,
    (const void *) SSL_new_listener_from,
    (const void *) SSL_new_session_ticket,
    (const void *) SSL_new_stream,
    (const void *) SSL_peek,
    (const void *) SSL_peek_ex,
    (const void *) SSL_pending,
    (const void *) SSL_poll,
    (const void *) SSL_read,
    (const void *) SSL_read_early_data,
    (const void *) SSL_read_ex,
    (const void *) SSL_renegotiate,
    (const void *) SSL_renegotiate_abbreviated,
    (const void *) SSL_renegotiate_pending,
    (const void *) SSL_rstate_string,
    (const void *) SSL_rstate_string_long,
    (const void *) SSL_select_next_proto,
    (const void *) SSL_sendfile,
    (const void *) SSL_session_reused,
    (const void *) SSL_set0_CA_list,
    (const void *) SSL_set0_rbio,
    (const void *) SSL_set0_security_ex_data,
    (const void *) SSL_set0_tmp_dh_pkey,
    (const void *) SSL_set0_wbio,
    (const void *) SSL_set1_cert_comp_preference,
    (const void *) SSL_set1_client_cert_type,
    (const void *) SSL_set1_compressed_cert,
    (const void *) SSL_set1_host,
    (const void *) SSL_set1_initial_peer_addr,
    (const void *) SSL_set1_param,
    (const void *) SSL_set1_server_cert_type,
    (const void *) SSL_set_SSL_CTX,
    (const void *) SSL_set_accept_state,
    (const void *) SSL_set_allow_early_data_cb,
    (const void *) SSL_set_alpn_protos,
    (const void *) SSL_set_async_callback,
    (const void *) SSL_set_async_callback_arg,
    (const void *) SSL_set_bio,
    (const void *) SSL_set_block_padding,
    (const void *) SSL_set_block_padding_ex,
    (const void *) SSL_set_blocking_mode,
    (const void *) SSL_set_cert_cb,
    (const void *) SSL_set_cipher_list,
    (const void *) SSL_set_ciphersuites,
    (const void *) SSL_set_client_CA_list,
    (const void *) SSL_set_connect_state,
    (const void *) SSL_set_ct_validation_callback,
    (const void *) SSL_set_debug,
    (const void *) SSL_set_default_passwd_cb,
    (const void *) SSL_set_default_passwd_cb_userdata,
    (const void *) SSL_set_default_read_buffer_len,
    (const void *) SSL_set_default_stream_mode,
    (const void *) SSL_set_ex_data,
    (const void *) SSL_set_fd,
    (const void *) SSL_set_generate_session_id,
    (const void *) SSL_set_hostflags,
    (const void *) SSL_set_incoming_stream_policy,
    (const void *) SSL_set_info_callback,
    (const void *) SSL_set_max_early_data,
    (const void *) SSL_set_msg_callback,
    (const void *) SSL_set_not_resumable_session_callback,
    (const void *) SSL_set_num_tickets,
    (const void *) SSL_set_options,
    (const void *) SSL_set_post_handshake_auth,
    (const void *) SSL_set_psk_client_callback,
    (const void *) SSL_set_psk_find_session_callback,
    (const void *) SSL_set_psk_server_callback,
    (const void *) SSL_set_psk_use_session_callback,
    (const void *) SSL_set_purpose,
    (const void *) SSL_set_quic_tls_cbs,
    (const void *) SSL_set_quic_tls_early_data_enabled,
    (const void *) SSL_set_quic_tls_transport_params,
    (const void *) SSL_set_quiet_shutdown,
    (const void *) SSL_set_read_ahead,
    (const void *) SSL_set_record_padding_callback,
    (const void *) SSL_set_record_padding_callback_arg,
    (const void *) SSL_set_recv_max_early_data,
    (const void *) SSL_set_rfd,
    (const void *) SSL_set_security_callback,
    (const void *) SSL_set_security_level,
    (const void *) SSL_set_session,
    (const void *) SSL_set_session_id_context,
    (const void *) SSL_set_session_secret_cb,
    (const void *) SSL_set_session_ticket_ext,
    (const void *) SSL_set_session_ticket_ext_cb,
    (const void *) SSL_set_shutdown,
    (const void *) SSL_set_srp_server_param,
    (const void *) SSL_set_srp_server_param_pw,
    (const void *) SSL_set_ssl_method,
    (const void *) SSL_set_tlsext_max_fragment_length,
    (const void *) SSL_set_tlsext_use_srtp,
    (const void *) SSL_set_tmp_dh_callback,
    (const void *) SSL_set_trust,
    (const void *) SSL_set_value_uint,
    (const void *) SSL_set_verify,
    (const void *) SSL_set_verify_depth,
    (const void *) SSL_set_verify_result,
    (const void *) SSL_set_wfd,
    (const void *) SSL_shutdown,
    (const void *) SSL_shutdown_ex,
    (const void *) SSL_srp_server_param_with_username,
    (const void *) SSL_state_string,
    (const void *) SSL_state_string_long,
    (const void *) SSL_stateless,
    (const void *) SSL_stream_conclude,
    (const void *) SSL_stream_reset,
    (const void *) SSL_trace,
    (const void *) SSL_up_ref,
    (const void *) SSL_use_PrivateKey,
    (const void *) SSL_use_PrivateKey_ASN1,
    (const void *) SSL_use_PrivateKey_file,
    (const void *) SSL_use_RSAPrivateKey,
    (const void *) SSL_use_RSAPrivateKey_ASN1,
    (const void *) SSL_use_RSAPrivateKey_file,
    (const void *) SSL_use_cert_and_key,
    (const void *) SSL_use_certificate,
    (const void *) SSL_use_certificate_ASN1,
    (const void *) SSL_use_certificate_chain_file,
    (const void *) SSL_use_certificate_file,
    (const void *) SSL_use_psk_identity_hint,
    (const void *) SSL_verify_client_post_handshake,
    (const void *) SSL_version,
    (const void *) SSL_waiting_for_async,
    (const void *) SSL_want,
    (const void *) SSL_write,
    (const void *) SSL_write_early_data,
    (const void *) SSL_write_ex,
    (const void *) SSL_write_ex2,
    (const void *) TLS_client_method,
    (const void *) TLS_method,
    (const void *) TLS_server_method,
    (const void *) TLSv1_1_client_method,
    (const void *) TLSv1_1_method,
    (const void *) TLSv1_1_server_method,
    (const void *) TLSv1_2_client_method,
    (const void *) TLSv1_2_method,
    (const void *) TLSv1_2_server_method,
    (const void *) TLSv1_client_method,
    (const void *) TLSv1_method,
    (const void *) TLSv1_server_method,
    (const void *) d2i_SSL_SESSION,
    (const void *) d2i_SSL_SESSION_ex,
    (const void *) i2d_SSL_SESSION,
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
