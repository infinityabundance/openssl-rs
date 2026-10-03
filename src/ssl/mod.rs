//! Phase 14.1–14.10 — `ssl/`: the `libssl` object model, method tables, cipher/configuration
//! surface, record layer, handshake-state readers, the BIO pair, the DTLS layer and the init/error/
//! QUIC bridge.
//!
//! `docs/PHASE-14-SUBPHASES.md` section 2 gives 14.1 the `ssl_lib.c` unit (342 open rows) and 14.2
//! `methods.c` (21) plus `s3_lib.c` (3). The crate lays the authority's `ssl/` tree out as
//! `src/ssl/`, one module per translation unit (`ssl/ssl_lib.c` -> `src/ssl/ssl_lib.rs`), exactly as
//! `forensics/tools/phase14_obligations.py`'s `crate_module` maps it.
//!
//! ## Slice 1: what landed, and what is withheld by name
//!
//! 14.1 is the stratum's first unit and its working set is 342 exports over one translation unit.
//! This landing is **Slice 1** of that unit, and it is recorded here rather than implied: the
//! symbols below moved from the ledger's `open` set to its `implemented` set, and every other
//! `ssl_lib.c` export stays in the Phase 2 ABI scaffold (`artifacts/phase2/shell/libssl.shell.rs`),
//! which aborts when called. A scaffold is not a silent placeholder, so an unlanded arm fails
//! loudly rather than inventing an answer (`docs/CUSTODIAN_CONTRACT.md` section 5).
//!
//! **Landed, Slice 1 (the object model and its accessor/control/callback surface):**
//!
//! * *Lifecycle and identity* — `SSL_CTX_new`, `SSL_CTX_new_ex`, `SSL_CTX_up_ref`, `SSL_CTX_free`,
//!   `SSL_new`, `SSL_free`, `SSL_up_ref`, `SSL_get_SSL_CTX`, `SSL_CTX_get_ssl_method`,
//!   `SSL_get_ssl_method`, `SSL_set_ssl_method`, `SSL_is_tls`, `SSL_is_dtls`, `SSL_is_quic`,
//!   `SSL_get_default_timeout`, `SSL_clear`.
//! * *Ex-data and the security attribute block* — `SSL_[CTX_]set/get_ex_data`,
//!   `SSL_[CTX_]set0/get0_security_ex_data`, `SSL_[CTX_]set/get_security_level`,
//!   `SSL_[CTX_]set/get_security_callback`.
//! * *Options, mode, verify, quiet-shutdown, shutdown and read-ahead* — `SSL_[CTX_]get/set/clear_options`,
//!   `SSL_[CTX_]get_verify_mode`/`_depth`/`_callback`, `SSL_[CTX_]set_verify`, `SSL_[CTX_]set_verify_depth`,
//!   `SSL_CTX_set_cert_verify_callback`, `SSL_[CTX_]set/get_quiet_shutdown`, `SSL_set/get_shutdown`,
//!   `SSL_[CTX_]get/set_read_ahead`, `SSL_CTX_set1_param`, `SSL_get0_param`, `SSL_CTX_get0_param`,
//!   `SSL_set_verify_result`, `SSL_get_verify_result`.
//! * *The control surface* — `SSL_ctrl`, `SSL_callback_ctrl`, `SSL_CTX_ctrl`, `SSL_CTX_callback_ctrl`.
//! * *Session-id context and the session-id generator* — `SSL_[CTX_]set_session_id_context`,
//!   `SSL_[CTX_]set_generate_session_id`.
//! * *Ticket/early-data accessors* — `SSL_CTX_set/get_num_tickets`, `SSL_set/get_num_tickets`,
//!   `SSL_[CTX_]set/get_max_early_data`, `SSL_[CTX_]set/get_recv_max_early_data`.
//! * *Version and state readers* — `SSL_version`, `SSL_client_version`, `SSL_get_version`,
//!   `SSL_session_reused`, `SSL_is_server`, `SSL_want`, `SSL_get_error`, `SSL_pending`,
//!   `SSL_has_pending`, `SSL_get_finished`, `SSL_get_peer_finished`.
//! * *The callback setters and their getters* — the default-passwd, info, msg, keylog, client-hello,
//!   cert, PSK (client/server/find/use), async, not-resumable, security, record-padding,
//!   ALPN-select, session-ticket and allow-early-data callbacks, and the security-ex-data setter.
//! * *The BIO plumbing* — `SSL_set0_rbio`, `SSL_set0_wbio`, `SSL_set_bio`, `SSL_get_rbio`,
//!   `SSL_get_wbio`, `SSL_get_fd`, `SSL_get_rfd`, `SSL_get_wfd`, `SSL_set_fd`, `SSL_set_wfd`,
//!   `SSL_set_rfd`.
//! * *The error/read/write entry guards* — `SSL_read`, `SSL_read_ex`, `SSL_peek`, `SSL_peek_ex`,
//!   `SSL_write`, `SSL_write_ex`, `SSL_write_ex2`, `SSL_do_handshake`, `SSL_shutdown`.
//! * *Certificate and store accessors* — `SSL_get_certificate`, `SSL_get_privatekey`,
//!   `SSL_CTX_get0_certificate`, `SSL_CTX_get0_privatekey`, `SSL_CTX_get_cert_store`,
//!   `SSL_CTX_set_cert_store`, `SSL_CTX_set1_cert_store`, `SSL_get0_verified_chain`.
//!
//! **Withheld by name, each with the later-stratum dependency that blocks it:**
//!
//! * `SSL_accept`, `SSL_connect`, `SSL_set_accept_state`, `SSL_set_connect_state`,
//!   `SSL_key_update`, `SSL_get_key_update_type`, `SSL_renegotiate`, `SSL_renegotiate_abbreviated`,
//!   `SSL_renegotiate_pending`, `SSL_new_session_ticket`, `SSL_shutdown_ex` — the handshake state
//!   machine and its method table, 14.2 (`methods.c`, `s3_lib.c`) and 14.5 (`statem.c`).
//! * `SSL_CTX_set_cipher_list`, `SSL_set_cipher_list`, `SSL_get_ciphers`, `SSL_get_cipher_list`,
//!   `SSL_CTX_get_ciphers`, `SSL_get_shared_ciphers`, `SSL_get1_supported_ciphers`,
//!   `SSL_get_client_ciphers`, `SSL_get_current_cipher`, `SSL_get_pending_cipher`,
//!   `SSL_bytes_to_cipher_list` — the cipher tables and parser, 14.3 (`ssl_ciph.c`).
//! * `SSL_get_servername`, `SSL_get_servername_type`, `SSL_get0_alpn_selected`,
//!   `SSL_set_alpn_protos`, `SSL_export_keying_material*`, `SSL_get_client_random`,
//!   `SSL_get_server_random` — the record layer and the extension code, 14.4/14.5.
//! * `SSL_SESSION_*`, `SSL_copy_session_id`, `SSL_dup`, `SSL_set_SSL_CTX`,
//!   `SSL_CTX_sessions`, `SSL_has_matching_session_id`, `SSL_get0_peer_certificate`,
//!   `SSL_get_peer_cert_chain`, the `SSL_CTX_load_verify_*`/`_use_*` loaders, DANE and the
//!   certificate plumbing — 14.7 (`ssl_sess.c`, `ssl_cert.c`, `ssl_rsa.c`).
//! * The CT surface (`SSL_CTX_enable_ct`, `SSL_ct_is_enabled`, ...), the client-hello readers,
//!   the QUIC accessors (`SSL_new_stream`, `SSL_get_stream_*`, ...), the RPK and negotiated
//!   cert-type surface, `SSL_get_event_timeout` and the poll-descriptor readers.
//!
//! **A pulled-forward dependency, and why it is here rather than deferred.** Slice 1's court builds
//! its context with `TLS_method()`, which `methods.c` (14.2) owns. Without it the object model has
//! no constructor to allocate a method with (`SSL_CTX_new(NULL)` is the refusal arm, not a
//! context), so Slice 1 lands the one constructor it needs — `TLS_method` — in
//! `src/ssl/methods.rs` and records it as a measured correction to the plan's ordering. 14.2 then
//! lands the rest of that unit beside it.
//!
//! ## Slice 2: the verify, transparency, ALPN and connection-accessor surface
//!
//! Slice 2 lands the second, larger block of the unit: the remaining exports that can be stated
//! faithfully without a handshake, a cipher table or a session object. 126 symbols moved from the
//! ledger's `open` set to its `implemented` set; the ledger's own counts are the live record, and
//! the 52 `ssl_lib.c` rows left open are named with their blocking stratum below.
//!
//! **Landed, Slice 2:**
//!
//! * *The verify-parameter and hostname surface* — `SSL_[CTX_]set_purpose`, `SSL_[CTX_]set_trust`,
//!   `SSL_set1_host`, `SSL_add1_host`, `SSL_set_hostflags`, `SSL_get0_peername`; the store loaders
//!   `SSL_CTX_load_verify_file`/`_dir`/`_store`/`_locations` and `SSL_CTX_set_default_verify_paths`.
//! * *Certificate and private-key readers* — `SSL_[CTX_]check_private_key`, `SSL_certs_clear`,
//!   `SSL_get0_peer_certificate`, `SSL_get1_peer_certificate`, `SSL_get_peer_cert_chain`.
//! * *Certificate transparency* — `SSL_[CTX_]enable_ct`, `SSL_[CTX_]ct_is_enabled`,
//!   `SSL_[CTX_]set_ct_validation_callback`, `SSL_CTX_set_ctlog_list_file`,
//!   `SSL_CTX_set_default_ctlog_list_file`, `SSL_CTX_get0_ctlog_store`,
//!   `SSL_CTX_set0_ctlog_store`, `SSL_get0_peer_scts`. The SCT log store is now allocated by
//!   `SSL_CTX_new_ex` (`ssl_lib.c:4067`), as the authority allocates it.
//! * *ALPN, NPN and SNI* — `SSL_[CTX_]set_alpn_protos`, `SSL_get0_alpn_selected`,
//!   `SSL_CTX_set_next_proto_select_cb`, `SSL_CTX_set_next_protos_advertised_cb`,
//!   `SSL_get0_next_proto_negotiated`, `SSL_select_next_proto`, `SSL_get_servername`,
//!   `SSL_get_servername_type`.
//! * *The certificate-type lists* — `SSL_[CTX_]set1_{client,server}_cert_type`,
//!   `SSL_[CTX_]get0_{client,server}_cert_type`, `SSL_get_negotiated_{client,server}_cert_type`.
//! * *Configuration* — `SSL_CTX_set_domain_flags`, `SSL_CTX_get_domain_flags`,
//!   `SSL_get_domain_flags`, the four block-padding setters, `SSL_[CTX_]set_post_handshake_auth`.
//! * *The async, buffer, poll-descriptor and remaining state readers* — `SSL_waiting_for_async`,
//!   `SSL_get_async_status`, `SSL_get_all_async_fds`, `SSL_get_changed_async_fds`,
//!   `SSL_alloc_buffers`, `SSL_free_buffers`, `SSL_get_value_uint`, `SSL_set_value_uint`,
//!   `SSL_set_debug`, `SSL_get_blocking_mode`, `SSL_set_blocking_mode`, `SSL_handle_events`,
//!   `SSL_get_event_timeout`, `SSL_get_rpoll_descriptor`, `SSL_get_wpoll_descriptor`,
//!   `SSL_net_read_desired`, `SSL_net_write_desired`, `SSL_get_key_update_type`,
//!   `SSL_renegotiate_pending`, `SSL_get_early_data_status`, `SSL_get_handshake_rtt`,
//!   `SSL_get_client_random`, `SSL_get_server_random`.
//! * *The QUIC-dispatch arms that answer for a non-QUIC object* — `SSL_new_listener[_from]`,
//!   `SSL_new_from_listener`, `SSL_new_domain`, `SSL_accept_connection`, `SSL_listen`,
//!   `SSL_get_accept_connection_queue_len`, `SSL_new_stream`, `SSL_accept_stream`,
//!   `SSL_stream_conclude`, `SSL_stream_reset`, `SSL_get_stream_type`/`_id`/`_read_state`/
//!   `_write_state`/`_read_error_code`/`_write_error_code`, `SSL_is_stream_local`,
//!   `SSL_set_default_stream_mode`, `SSL_set_incoming_stream_policy`, `SSL_get0_connection`/
//!   `_listener`/`_domain`, `SSL_is_connection`/`_listener`/`_domain`, `SSL_shutdown_ex`,
//!   `SSL_set1_initial_peer_addr`, `SSL_get_conn_close_info`.
//! * *PSK identity and the session master key* — `SSL_[CTX_]use_psk_identity_hint`,
//!   `SSL_get_psk_identity`, `SSL_get_psk_identity_hint`, `SSL_SESSION_get_master_key`,
//!   `SSL_SESSION_set1_master_key`.
//! * *The ClientHello readers* — `SSL_client_hello_isv2`, `SSL_client_hello_get0_legacy_version`,
//!   `_get0_random`, `_get0_session_id`, `_get0_ciphers`, `_get0_compression_methods`,
//!   `_get1_extensions_present`, `_get_extension_order`, `_get0_ext`.
//!
//! **Withheld from Slice 2, with the later-stratum dependency that blocks each group:**
//!
//! * the cipher surface (`SSL_[CTX_]set_cipher_list`, `SSL_CTX_get_ciphers`, `SSL_get_ciphers`,
//!   `SSL_get_cipher_list`, `SSL_get_shared_ciphers`, `SSL_get1_supported_ciphers`,
//!   `SSL_get_client_ciphers`, `SSL_get_current_cipher`, `SSL_get_pending_cipher`,
//!   `SSL_get_current_compression`, `SSL_get_current_expansion`, `SSL_bytes_to_cipher_list`,
//!   `SSL_CTX_set_ssl_version`) — the cipher tables and parser, 14.3 (`ssl_ciph.c`).
//! * the handshake entry points (`SSL_accept`, `SSL_connect`, `SSL_set_accept_state`,
//!   `SSL_set_connect_state`, `SSL_key_update`, `SSL_renegotiate`, `SSL_renegotiate_abbreviated`,
//!   `SSL_new_session_ticket`, `SSL_stateless`, `SSL_read_early_data`, `SSL_write_early_data`,
//!   `SSL_export_keying_material`, `SSL_export_keying_material_early`,
//!   `SSL_verify_client_post_handshake`, `SSL_sendfile`) — the state machine and record layer,
//!   14.4/14.5 (`statem.c`, `rec_layer_s3.c`).
//! * the DANE record surface (`SSL_CTX_dane_enable`, `SSL_CTX_dane_mtype_set`,
//!   `SSL_CTX_dane_set_flags`, `SSL_CTX_dane_clear_flags`, `SSL_dane_enable`,
//!   `SSL_dane_set_flags`, `SSL_dane_clear_flags`, `SSL_dane_tlsa_add`, `SSL_get0_dane`,
//!   `SSL_get0_dane_authority`, `SSL_get0_dane_tlsa`, `SSL_add_expected_rpk`) and
//!   `SSL_get0_peer_rpk` — the DANE container and the certificate path, 14.7.
//! * `SSL_CTX_sessions`, `SSL_has_matching_session_id`, `SSL_copy_session_id`, `SSL_dup`,
//!   `SSL_set_SSL_CTX`, `SSL_set0_tmp_dh_pkey`, `SSL_CTX_set0_tmp_dh_pkey` — the session and
//!   certificate plumbing (and its `ssl_security` check), 14.7.
//! * `SSL_CTX_set_default_verify_file`/`_dir`/`_store` — the `X509_LOOKUP`-level default loaders,
//!   withheld with the DANE/default-path work rather than approximated.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **`SSL_CTX_new_ex` allocates less than the authority.** The authority's `SSL_CTX_new_ex`
//!   (`ssl_lib.c:3989-4331`) loads the cipher, group and sigalg tables (`ssl_load_ciphers`,
//!   `ssl_load_groups`, `ssl_load_sigalgs`) and installs the default cipher list; those units are
//!   14.3's and 14.5's, so this slice allocates the object, its `X509_VERIFY_PARAM`, its
//!   `X509_STORE`, its `CERT` and its ex-data, and reproduces the authority's
//!   *observable* defaults (`mode`, `session_cache_mode`, `session_cache_size`, `session_timeout`,
//!   `max_cert_list`, `verify_mode`, the `SSL_OP_NO_COMPRESSION | SSL_OP_ENABLE_MIDDLEBOX_COMPAT`
//!   option set, `num_tickets = 2`, `max_early_data = 0`, `recv_max_early_data = 16384`,
//!   `max_send_fragment = split_send_fragment = SSL3_RT_MAX_PLAIN_LENGTH`). It does not build a
//!   cipher list, so `SSL_CTX_get_ciphers` (14.3, withheld) would not agree and is not landed.
//! * **`SSL_new` does not run the method's `ssl_init`/`ssl_reset`.** Those are `tls1_new` and
//!   `ossl_ssl_connection_reset` (`s3_lib.c`), which the record layer and the state machine
//!   (`ossl_statem_clear`, `RECORD_LAYER_reset`) are reached from. This slice copies the
//!   connection's configuration from the context, sets `version = method->version`, and leaves
//!   `handshake_func` NULL — which is the authority's post-`SSL_new` state, so the read/write and
//!   handshake guards (`SSL_R_UNINITIALIZED`, `SSL_R_CONNECTION_TYPE_NOT_SET`) are the authority's.
//!   The record-layer half of `handshake_func` is 14.5's.
//! * **The control surface's fall-through arm is not the authority's.** For a command not in the
//!   explicit switch, the authority calls `method->ssl_ctrl`/`ssl_ctx_ctrl` (`ssl3_ctrl` /
//!   `ssl3_ctx_ctrl`); this slice returns the same `0` the method would for a command it does not
//!   know, but a command `ssl3_*_ctrl` *does* implement (the DH/ECDH temp-key and ticket-key setters,
//!   for example) would diverge. The differential court drives only commands the explicit switch
//!   answers.
//! * **The candidate DSO duplicates the crate's error state, so a libssl `ERR` raise is invisible to
//!   the distribution's error queue.** `forensics/tools/build_phase2.sh` links the crate archive into
//!   `libssl.so.3` with `--whole-archive` (the `#[no_mangle]` entry points are referenced by nothing,
//!   so the linker would otherwise discard them), and `libcrypto.so.3` links its own copy of the same
//!   archive. The version script's `local: *;` hides the duplicate symbols, but the *state* is
//!   duplicated: `ERR_raise` from this unit writes the archive copy inside `libssl.so.3`, while a
//!   consumer's `ERR_peek_error`/`ERR_clear_error` resolve to `libcrypto.so.3`. The raises here are
//!   still the authority's coordinates and are kept; the divergence is the link, and it is recorded
//!   here (the WIP link is preserved in `d181e440` and the manifest's own comment says so) rather
//!   than hidden. The `RT-SSL-OBJECT` court therefore does not compare an error-observing arm.
//!
//! **Slice 2's measured divergences, recorded rather than hidden.**
//!
//! * **`SSL_certs_clear` clears only the active leaf.** The authority calls `ssl_cert_clear_certs`,
//!   which also frees the extra key slots and the `custext` list (`ssl_cert.c`, 14.7); only the one
//!   leaf pair exists in this slice, so the function clears `cert->key.x509`/`privatekey` and nothing
//!   else. A consumer that had installed extra certificates would see a difference; none can be
//!   installed here.
//! * **`SSL_get0_peer_scts` reports the parsed list it has and marks it parsed.** The authority's
//!   extraction reads the TLS extension (14.5), the OCSP response and the certificate's `X509v3`
//!   extensions (14.7); with no peer those sources are empty, so the NULL answer is the authority's
//!   for the states this slice can reach.
//! * **The CT callback installers omit the custom-extension and OCSP-status preconditions.**
//!   `SSL_[CTX_]set_ct_validation_callback` in the authority refuses when a custom handler for the
//!   SCT extension is registered (`SSL_CTX_has_client_custom_ext`, 14.9) and, for a connection,
//!   requests the OCSP status type (`SSL_set_tlsext_status_type`, 14.9). This slice installs no
//!   custom extensions, so the refusal is unreachable; the OCSP request is deferred with the
//!   extension code. `ct_strict` likewise cannot see a parsed SCT stack and answers the authority's
//!   own `SSL_R_NO_VALID_SCTS` refusal for an empty list.
//! * **`SSL_alloc_buffers`/`SSL_free_buffers` answer 1 without touching a record layer.** The
//!   authority calls the read/write record methods' `alloc_buffers`/`free_buffers`; the record layer
//!   is 14.4's. A fresh connection holds no buffers and the authority's methods free nothing, so 1
//!   is its answer for the states the court drives.
//! * **`SSL_handle_events` answers 1 without the DTLS timeout path.** The authority's DTLS arm calls
//!   `DTLSv1_handle_timeout` (14.8); for the TLS methods this slice builds the authority also
//!   answers 1.
//! * **The domain-flag setters/getters take the non-QUIC arm.** `SSL_CTX_set_domain_flags`,
//!   `SSL_CTX_get_domain_flags` and `SSL_get_domain_flags` are `IS_QUIC`/`IS_QUIC_CTX` properties;
//!   for the TLS objects this crate builds the authority raises `ERR_R_UNSUPPORTED` (the two
//!   `SSL_CTX` forms) and answers 0 (the connection form), which this slice reproduces.
//! * **`SSL_get_servername` is reduced to the pre-handshake client arm.** With `handshake_func`
//!   never installed (14.5) the authority's `server` test is always the client path and
//!   `SSL_in_before` is always true, so the server, hit and post-handshake branches its doc comment
//!   describes are unreachable here.
//! * **`SSL_set0_tmp_dh_pkey`/`SSL_CTX_set0_tmp_dh_pkey` are withheld, not approximated.** Both run
//!   `ssl_security(..., SSL_SECOP_TMP_DH, ...)` before storing (`ssl_lib.c:7595`, `:7607`); the
//!   security check is 14.7's, so storing without it would not be the authority's answer.
//! * **`SSL_set1_client_cert_type`'s helpers are this file's own.** `validate_cert_type` and
//!   `set_cert_type` are file-static in the authority; they are private functions here with the same
//!   body.
//!
//! ## 14.2: the method and version tables
//!
//! 14.2 lands `methods.c` and `s3_lib.c`. **`methods.c`** is `src/ssl/methods.rs`: the 21 exported
//! `TLS_*`/`DTLS_*`/`TLSv1_*` constructors and the static tables the `IMPLEMENT_*_meth_func` macros
//! build (`ssl_local.h:2344-2464`). **`s3_lib.c`** is `src/ssl/s3_lib.rs`: `SSL_CTX_set_tlsext_ticket_key_evp_cb`,
//! `SSL_get0_group_name` and `SSL_group_to_name`.
//!
//! **A correction 14.2 makes to the object model, and why.** `SSL_new` (`src/ssl/ssl_lib.rs`) now
//! installs the method family's maximum protocol version for both any-version spellings: the
//! authority's `tls1_clear` (`t1_lib.c:136-139`) maps `TLS_ANY_VERSION` to `TLS_MAX_VERSION_INTERNAL`
//! and `dtls1_clear` (`d1_lib.c:217-218`) maps `DTLS_ANY_VERSION` to `DTLS_MAX_VERSION_INTERNAL`.
//! Slice 1 carried only the TLS rule because `DTLS_method` did not exist yet; `DTLS_method` is
//! 14.2's, so the DTLS rule lands with it.
//!
//! **The ticket-key callback is stored on the context.** `SSL_CTX_set_tlsext_ticket_key_evp_cb`
//! writes `ctx->ext.ticket_key_evp_cb`, so `SslCtx` gains one field (`ticket_key_evp_cb`) and the
//! `TicketKeyEvpCb` type alias. The authority exposes no getter for it; the court drives the
//! setter's return only, and the handshake path that would observe the callback is 14.7's.
//!
//! **The group table is 14.5's, so the two group-name accessors reduce to NULL.** `SSL_CTX_new_ex`
//! does not run `ssl_load_groups`, so `ctx->group_list` is empty and every lookup misses; the
//! court drives only the unknown-NID arms and names the known-NID arm `pending`. See
//! `src/ssl/s3_lib.rs` for the full divergence record.
//!
//! ## 14.3: the cipher and configuration surface
//!
//! 14.3 lands `ssl_ciph.c` and `ssl_conf.c`, plus the five `ssl_lib.c` cipher-list accessors the
//! plan already names 14.3's. **`ssl_ciph.c`** is `src/ssl/ssl_ciph.rs`: the three built-in
//! ciphersuite tables (`tls13_ciphers`, `ssl3_ciphers`, `ssl3_scsvs`, emitted by
//! `forensics/tools/gen_phase14_cipher_tables.py` into the generated `src/ssl/ssl_ciph_table.rs`
//! with the four mask-to-NID tables, the alias table and the named masks), the `SSL_CIPHER_*`
//! readers, `OPENSSL_cipher_name`, the `OSSL_default_*` lists, `SSL_CIPHER_find`,
//! `SSL_CTX_set_ciphersuites`/`SSL_set_ciphersuites`, the `SSL_COMP_*` surface and the rule engine
//! (`ssl_load_ciphers`, `ssl_create_cipher_list`, `ssl_cipher_process_rulestr`). **`ssl_conf.c`**
//! is `src/ssl/ssl_conf.rs`: the `SSL_CONF_CTX_*` lifecycle and flag accessors, the full command
//! table, and `SSL_CONF_cmd`/`SSL_CONF_cmd_value_type`/`SSL_CONF_cmd_argv`.
//!
//! **The five pulled-forward accessors, and why.** `SSL_CTX_set_cipher_list`, `SSL_set_cipher_list`,
//! `SSL_CTX_get_ciphers`, `SSL_get_ciphers` and `SSL_get_cipher_list` are defined by `ssl_lib.c`
//! (14.1's unit) but the plan names them 14.3's ("the cipher tables and parser, 14.3") and the
//! court drives them, so they are landed in `src/ssl/ssl_lib.rs` and recorded here as a measured
//! correction, as 14.1's `TLS_method` was.
//!
//! **The tables carry the post-`ssl_sort_cipher_list` order.** The authority qsorts the three
//! static tables by `id` at init (`s3_lib.c:3729-3736`); `ssl3_get_cipher(u)` reverses the *sorted*
//! table, so the generator emits the sorted arrays the readers and the parser actually see. Sorting
//! at emission rather than at first call keeps the candidate free of one-time init state.
//!
//! **Measured divergences, recorded rather than hidden.**
//!
//! * **`ssl_load_ciphers` records the disabled masks, not the fetched method pointers.** The
//!   authority keeps the fetched `EVP_CIPHER`/`EVP_MD` in `ctx->ssl_cipher_methods[]`/
//!   `ssl_digest_methods[]` for the record layer; those arrays are 14.4's, so this slice performs
//!   the same fetches to compute the four masks and frees the objects. The default preference list
//!   the parser builds is nevertheless the authority's, which `RT-SSL-CIPH` compares.
//! * **`SSL_CONF`'s certificate-, key-, signature-algorithm- and group-loading commands are not
//!   wired.** Their table rows are present (so recognition and `SSL_CONF_cmd_value_type` are the
//!   authority's) but their handlers return the authority's failure value, because their named
//!   units are 14.5/14.7's. See `src/ssl/ssl_conf.rs`.
//! * **`ssl_set_version_bound` is pulled forward from 14.5.** `min_protocol`/`max_protocol` call it
//!   (`ssl/statem/statem_lib.c:2107-2156`); it is transcribed in `src/ssl/ssl_conf.rs`.
//!
//! ## 14.4: the record layer
//!
//! 14.4 lands the two units the plan names. **`ssl/record/rec_layer_s3.c`** is
//! `src/ssl/record/rec_layer_s3.rs`: `SSL_CTX_set_default_read_buffer_len`,
//! `SSL_set_default_read_buffer_len`, `SSL_rstate_string` and `SSL_rstate_string_long`.
//! **`ssl/rio/poll_immediate.c`** is `src/ssl/rio/poll_immediate.rs`: the non-QUIC `SSL_poll`
//! readout and its refusal arms. Each file records its own measured divergences: the record read
//! state is not modelled, so the state strings answer `"unknown"` (the authority's own answer with
//! no record-read method installed); the buffer-length setter has no public reader on either side;
//! and `SSL_poll`'s QUIC and blocking arms are unreachable for objects this crate builds.
//! Its court is `RT-RECORD` (`courts/phase14/rt_record_probe.c`), registered in
//! `forensics/tools/phase14_courts.py`.
//!
//! ## 14.5: the handshake state machine
//!
//! 14.5 lands the three units the plan names. **`ssl/statem/statem.c`** is `src/ssl/statem/statem.rs`:
//! the four state readers (`SSL_get_state`, `SSL_in_before`, `SSL_in_init`, `SSL_is_init_finished`),
//! reading three state words `SSL_new` installs to the authority's post-`SSL_new` values.
//! **`ssl/statem/extensions_cust.c`** is `src/ssl/statem/extensions_cust.rs`: the custom-extension
//! registration surface, which required a `custext` record list on `Cert`. **`ssl/t1_lib.c`** is
//! `src/ssl/t1_lib.rs`: the MFL accessors, the sigalg readers, `SSL_check_chain`'s refusal arms and
//! the provider-probing `SSL_get1_builtin_sigalgs`. Each file records its own divergences: the sigalg
//! lookup cache is not loaded (14.1's recorded `SSL_CTX_new_ex` divergence), `SSL_check_chain` lands
//! only its refusal arms, and the GOST rows of the sigalg table are omitted because the admitted
//! authority's default provider publishes neither their digests nor their key types.
//! Its court is `RT-STATEM` (`courts/phase14/rt_statem_probe.c`), registered in
//! `forensics/tools/phase14_courts.py`.
//!
//! ## 14.6: the BIO pair and buffers
//!
//! 14.6 lands the whole of `ssl/bio_ssl.c` as `src/ssl/bio_ssl.rs`: the `"ssl"` `BIO_METHOD` and
//! its seven callbacks, the `BIO_SSL` record with the authority's renegotiation counters, the four
//! constructors and the two session controls. It needed two internal helpers in this crate's
//! `ssl_lib.rs` — `ssl_set_accept_state`/`ssl_set_connect_state` (whose public `SSL_set_*_state`
//! rows stay open) and a reduced `ssl_copy_session_id` for the reachable fresh-connection arm —
//! rather than the still-open public entries. `src/ssl/bio_ssl.rs` records the four reductions:
//! the renegotiation trigger never fires, `BIO_CTRL_DUP` and `BIO_CTRL_RESET`'s role restore are
//! reduced, and the session copy is that reduced body. Its court is `RT-SSL-BIO`
//! (`courts/phase14/rt_ssl_bio_probe.c`), registered in `forensics/tools/phase14_courts.py`.
//!
//! ## 14.8: the DTLS layer
//!
//! 14.8 lands the two DTLS units. **`ssl/d1_lib.c`** is `src/ssl/d1_lib.rs`: `DTLSv1_listen`, the
//! data-MTU and timer-callback entry points, and the internal `dtls1_new_state`/`dtls1_free` that
//! `SSL_new`/`SSL_free` call for a DTLS method. **`ssl/d1_srtp.c`** is `src/ssl/d1_srtp.rs`: the
//! twelve-profile table, the `:`-separated name parser and the four profile entries. Each records
//! its divergences: `DTLSv1_listen` is reduced past the cookie stage (which needs `WPACKET` and the
//! record layer), and the `IS_QUIC_METHOD` and negotiated-profile arms are unreachable. Its court
//! is `RT-DTLS` (`courts/phase14/rt_dtls_probe.c`), registered in
//! `forensics/tools/phase14_courts.py`.
//!
//! ## 14.10: the init, error and QUIC bridge
//!
//! 14.10 lands four units. **`ssl/ssl_init.c`** is `src/ssl/ssl_init.rs`: `OPENSSL_init_ssl`, with the
//! authority's option folding and one base `RUN_ONCE` (the dead `stopped` arm and
//! `ssl_sort_cipher_list` are recorded reductions). **`ssl/ssl_err_legacy.c`** is
//! `src/ssl/ssl_err_legacy.rs`: `ERR_load_SSL_strings`. **`ssl/quic/quic_tls_api.c`** and
//! **`ssl/quic/quic_impl.c`** are `src/ssl/quic/quic_tls_api.rs` and `src/ssl/quic/quic_impl.rs`:
//! the QUIC TLS accessors and `SSL_inject_net_dgram`, reduced to their refusal arms because the
//! object the success arms drive is Phase 15's. Its court is `RT-SSL-INIT`
//! (`courts/phase14/rt_ssl_init_probe.c`), registered in `forensics/tools/phase14_courts.py`.
//!
//! ## 14.7: the session and certificate plumbing (the largest subphase, landed in four slices)
//!
//! 14.7 is 124 open rows over seven units. It lands in four ordered slices, recorded here because
//! the unit is never left half-transcribed without the record:
//!
//! **Slice 1 — the session object, the DER codec and the printers** (71 rows). `ssl/ssl_sess.c`
//! is `src/ssl/ssl_sess.rs`: `SSL_SESSION_new`/`_free`/`_up_ref`/`_dup` and `ssl_session_dup_intern`,
//! the whole accessor surface (id, id-context, master key via `ssl_lib.rs`, hostname, ALPN, ticket
//! appdata, time/timeout, protocol version, cipher, early data, compress id, peer/peer-rpk),
//! ex-data, the per-context internal cache (`SSL_CTX_add_session`/`_remove_session`/
//! `_flush_sessions[_ex]` and the `remove_session_locked` helper), `SSL_get_session`/`_get1_session`/
//! `SSL_set_session`, the callback setters and their getters, `SSL_set_session_secret_cb`/
//! `_ticket_ext_cb`/`_ticket_ext`, and the four PEM entry points the `IMPLEMENT_PEM_rw` macro
//! generates. `ssl/ssl_asn1.c` is `src/ssl/ssl_asn1.rs`: the `SSL_SESSION_ASN1` template and
//! `i2d_SSL_SESSION`/`d2i_SSL_SESSION`/`d2i_SSL_SESSION_ex`. `ssl/ssl_txt.c` is
//! `src/ssl/ssl_txt.rs`: `SSL_SESSION_print`/`_fp`/`_keylog`.
//!
//! **Slice 2 — the certificate-compression substrate and its exports** (8 rows).
//! `ssl/ssl_cert_comp.c` is `src/ssl/ssl_cert_comp.rs`: the `OSS_COMP_CERT` record and its
//! `new`/`free`/`up_ref` helpers, `ossl_calculate_comp_expansion`/`ossl_comp_has_alg` and the eight
//! exports. It landed with Slice 1 because `CertKey` carries the `comp_cert[]` slots. **The
//! admitted build defines `OPENSSL_NO_COMP_ALG`** (`configuration.h:198-202`), so every export's
//! `#ifndef` body is not compiled and each answers 0; the transcribed bodies behind the guard are
//! recorded, not compiled.
//!
//! **Slice 3 — the CA-list and certificate-subject plumbing** (20 rows). `ssl/ssl_cert.c` is
//! `src/ssl/ssl_cert.rs`: the `X509_STORE_CTX` ex-data index, the `SSL[_CTX]_[set0|get0|add1|add]_
//! CA_list`/`client_CA` surface, `SSL_dup_CA_list`, the four subject-list loaders, and the internal
//! helpers `ssl_cert_lookup_by_pkey`/`ssl_security`/`ssl_ctx_security`/`ssl_security_cert` that
//! `ssl_rsa.c` and `t1_lib.c` reach.
//!
//! **Slice 4 — the certificate and private-key loaders** (25 rows). `ssl/ssl_rsa.c` is
//! `src/ssl/ssl_rsa.rs` (19 rows): the in-memory `SSL[_CTX]_use_certificate*`/`use_PrivateKey*`
//! surface, the `use_certificate_chain_file` spellings, the serverinfo installers and
//! `SSL[_CTX]_use_cert_and_key`. `ssl/ssl_rsa_legacy.c` is `src/ssl/ssl_rsa_legacy.rs` (6 rows):
//! the deprecated `use_RSAPrivateKey` spellings. The `Cert`/`CertKey` records grew the `pkeys[]`
//! array, `key_index`, `references`, `cert_comp_prefs`, the per-slot `chain`/`serverinfo`/
//! `comp_cert[]`, and `SSL_new`'s reduced `cert_copy_security` now **up-refs** the active leaf pair
//! so a connection's `cert_free` cannot free the context's objects (the borrowed-copy double free
//! the `RT-SESSION-CERT` court caught).
//!
//! After Slice 4 the ledger's `open_in_this_stratum` stands at 79, all of them 14.9's and 14.11's
//! and 14.1's remaining units; the seven 14.7 units are closed. The court is `RT-SESSION-CERT`
//! (`courts/phase14/rt_session_cert_probe.c`), registered in `forensics/tools/phase14_courts.py`.
//!
//! **14.7's measured divergences, recorded rather than hidden.**
//!
//! * **The session cache is an `OpenSslStack` searched linearly, not an `LHASH`.** The authority
//!   keys an lhash on `(ssl_version, session_id)` (`ssl_lib.c:3854`, `:3877`) and keeps a
//!   `calc_timeout`-ordered doubly linked list; this crate compares the same two fields in a linear
//!   scan. Eviction and `SSL_CTX_flush_sessions_ex` process insertion order, not `calc_timeout`
//!   order; no court arm depends on the eviction order. See `src/ssl/ssl_sess.rs`.
//! * **The session's `time`/`timeout`/`calc_timeout` are seconds, not `OSSL_TIME` nanoseconds.**
//!   Every reader converts to `time_t`, so the codec and the accessors agree.
//! * **`ssl_generate_session_id`/`ssl_get_new_session` are not landed.** They are internal to
//!   `ssl_sess.c` and drive the handshake; no exported row names them.
//! * **The certificate security check reduces to the crate's default callback.**
//!   `ssl_security_cert` calls the `Cert`'s `sec_cb`, which `ssl_lib.rs` initialises to a callback
//!   that answers 1 for every operation (14.1's recorded reduction), so a weak-key rejection the
//!   authority would raise is accepted. The court's fixtures are strong keys, where both sides
//!   answer 1.
//! * **`ssl_cert_lookup_by_pkey` adds an id comparison.** The authority matches through
//!   `EVP_PKEY_is_a` alone; this crate's `evp_pkey_name2type` (Phase 8) answers `NID_undef` for
//!   `"rsaEncryption"`/`"rsassaPss"` on a legacy key, so the key id and base id are compared as a
//!   fallback. The table row is the same for every classic type.
//! * **The file/dir/store subject loaders read the filesystem and are only driven at their
//!   refusal arms.** `SSL_load_client_CA_file[_ex]` and `SSL_add_file_cert_subjects_to_stack`
//!   open a file, `SSL_add_dir_cert_subjects_to_stack` walks a directory, and
//!   `SSL_add_store_cert_subjects_to_stack` walks an `OSSL_STORE` URI; duplicate detection is a
//!   linear `X509_NAME_cmp` scan rather than an `LHASH_OF(X509_NAME)`.
//! * **`use_certificate_chain_file` installs the leaf and skips the chain walk.**
//!   `SSL_CTX_clear_chain_certs`/`SSL_CTX_add0_chain_cert` are still-open `ssl_lib.c` rows.
//! * **The serverinfo add callback reports no serverinfo data.** The authority reads
//!   `ssl_get_server_cert_serverinfo`, a helper this crate does not land; with no handshake the
//!   callback is never invoked. The installer's validation and storage are the authority's.
//! * **`SSL_set1_compressed_cert`/the compression exports answer the `OPENSSL_NO_COMP_ALG`
//!   refusal.** The admitted build defines it, so every `ssl_cert_comp.c` export answers 0.
//!
//! ## 14.9: the TLS extension, SRP and diagnostic glue
//!
//! 14.9 lands five units. **`ssl/tls_srp.c`** is `src/ssl/tls_srp.rs` (19 rows): the credential and
//! callback surface over the authority's `SRP_CTX` block (`ssl_local.h:571-586`), now a field on
//! both `SslCtx` and `Ssl`; the context setters reproduce `ssl3_ctx_ctrl`/`ssl3_ctx_callback_ctrl`
//! (`src/ssl/ssl_lib.rs`), and `SSL_new` copies the context block onto the connection as `ssl3_new`
//! does. **`ssl/ssl_stat.c`** is `src/ssl/ssl_stat.rs` (6 rows): the state and alert string tables in
//! full. **`ssl/ssl_mcnf.c`** is `src/ssl/ssl_mcnf.rs` (3 rows): `SSL_add_ssl_module`'s no-op and
//! `ssl_do_config`, wired into `SSL_CTX_new_ex` as `ssl_lib.c:4280` wires `ssl_ctx_system_config`.
//! **`ssl/tls_depr.c`** is `src/ssl/tls_depr.rs` (3 rows): `SSL_CTX_set_client_cert_engine` and the
//! deprecated temporary-DH callback setters. **`ssl/t1_trce.c`** is `src/ssl/t1_trce.rs` (1 row):
//! `SSL_trace`, the whole decoder.
//!
//! Its court is `RT-SSL-EXT` (`courts/phase14/rt_ssl_ext_probe.c`), registered in
//! `forensics/tools/phase14_courts.py`.
//!
//! **14.9's measured divergences, recorded rather than hidden.**
//!
//! * **The candidate's libssl carries its own copy of the `ssl_conf` store.** The whole-archive
//!   link duplicates the crate's globals across `libssl.so.3` and `libcrypto.so.3` (the same
//!   duplication the error-state note above records), so a command set loaded through libcrypto's
//!   `CONF_modules_load_file` is not visible to libssl's `SSL_CTX_config`. The authority's libssl
//!   imports `conf_ssl_name_find`/`conf_ssl_get`/`conf_ssl_get_cmd` from libcrypto; the candidate
//!   binds its own local copies. `RT-SSL-EXT` therefore compares `SSL_CTX_config`'s refusal arms,
//!   which read the same (empty) store on both sides, and names the success arm `pending`.
//! * **`SSL_trace`'s key-exchange arm answers `UNKNOWN`.** `ssl_get_keyex` reads
//!   `sc->s3.tmp.new_cipher`, which is NULL before a handshake; the authority would fault, so the
//!   court never hands `SSL_trace` a `ClientKeyExchange`/`ServerKeyExchange`, and the transcribed
//!   helper answers `UNKNOWN`/0 for the states this crate reaches. No arm of `RT-SSL-EXT` drives it.
//! * **`SSL_get_current_compression`/`SSL_get_current_expansion` answer NULL.** The authority asks
//!   the record layer's compression callback; this crate models no record method, and the
//!   authority's own default record method answers NULL for a connection with no negotiated
//!   compression.
//!
//! ## 14.1's remainder: what its landed dependencies unblock, and what still waits
//!
//! After 14.3/14.4/14.5/14.7 landed, eighteen more `ssl_lib.c` rows close: `SSL_CTX_sessions`,
//! `SSL_CTX_set_ssl_version`, `SSL_copy_session_id`, `SSL_has_matching_session_id`,
//! `SSL_get_client_ciphers`, `SSL_get_current_cipher`, `SSL_get_pending_cipher`,
//! `SSL_get_current_compression`, `SSL_get_current_expansion`, `SSL_get_shared_ciphers`,
//! `SSL_get0_peer_rpk`, `SSL_set0_tmp_dh_pkey`, `SSL_CTX_set0_tmp_dh_pkey`,
//! `SSL_CTX_set_default_verify_dir`/`_file`/`_store`, and the public `SSL_set_accept_state`/
//! `SSL_set_connect_state` over the internal helpers 14.6/14.8 already share. The chain-certificate
//! controls `SSL_CTX_clear_chain_certs`/`SSL_CTX_add0_chain_cert` (macros over `SSL_CTRL_CHAIN`/
//! `SSL_CTRL_CHAIN_CERT`) land as `ssl3_ctx_ctrl` arms over the `ssl_cert_set0_chain`/
//! `ssl_cert_add0_chain_cert`/`ssl_cert_add1_chain_cert` helpers added to `src/ssl/ssl_cert.rs`,
//! which lets `use_certificate_chain_file` read the trailing CA certificates as `ssl_rsa.c:546-573`
//! does.
//!
//! The rows that stay open are blocked by internals this stratum has not landed, not by a later
//! phase: the thirteen handshake entry points (`SSL_accept`, `SSL_connect`, `SSL_key_update`,
//! `SSL_renegotiate`/`_abbreviated`, `SSL_new_session_ticket`, `SSL_read_early_data`,
//! `SSL_write_early_data`, `SSL_export_keying_material`/`_early`, `SSL_sendfile`, `SSL_stateless`,
//! `SSL_verify_client_post_handshake`) need the state machine and record layer's *engine* —
//! `ssl/statem/statem.c` and `rec_layer_s3.c` landed their readers and framing surfaces, not a
//! runnable handshake — so calling one would start a handshake no arm can complete;
//! `SSL_bytes_to_cipher_list` and `SSL_get1_supported_ciphers` need `ssl_set_client_disabled`/
//! `SSL_cipher_disabled` (`t1_lib.c:2848`/`:2882`), whose `s3.tmp.mask_a`/`mask_k`/`min_ver`/
//! `max_ver` block this crate does not model (14.5's unit); `SSL_dup` and `SSL_set_SSL_CTX` need
//! `ssl_cert_dup` plus `custom_exts_copy_conn`/`custom_exts_copy_flags` (14.7's `ssl_cert.c`); and
//! the twelve DANE/RPK rows (`SSL_[CTX_]dane_*`, `SSL_get0_dane*`, `SSL_add_expected_rpk`) need
//! `SSL_set_tlsext_host_name`'s `SSL_ctrl` command (`SSL_CTRL_SET_TLSEXT_HOSTNAME`, unlanded) and the
//! certificate/public-key decode-and-insert path of `ssl_lib.c:264-443`. Each waits on its named
//! helper rather than an invented body.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod bio_ssl;
pub mod d1_lib;
pub mod d1_srtp;
pub mod methods;
pub mod quic;
pub mod record;
pub mod rio;
pub mod s3_lib;
pub mod ssl_asn1;
pub mod ssl_cert;
pub mod ssl_cert_comp;
pub mod ssl_ciph;
pub mod ssl_ciph_table;
pub mod ssl_conf;
pub mod ssl_err_legacy;
pub mod ssl_init;
pub mod ssl_lib;
pub mod ssl_mcnf;
pub mod ssl_rsa;
pub mod ssl_rsa_legacy;
pub mod ssl_sess;
pub mod ssl_stat;
pub mod ssl_txt;
pub mod statem;
pub mod t1_lib;
pub mod t1_trce;
pub mod tls_depr;
pub mod tls_srp;
