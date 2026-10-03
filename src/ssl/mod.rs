//! Phase 14.1 — `ssl/`: the `libssl` (`SSL_CTX`/`SSL`) object model.
//!
//! `docs/PHASE-14-SUBPHASES.md` section 2 gives 14.1 the `ssl_lib.c` unit (342 open rows). The
//! crate lays the authority's `ssl/` tree out as `src/ssl/`, one module per translation unit
//! (`ssl/ssl_lib.c` -> `src/ssl/ssl_lib.rs`), exactly as `forensics/tools/phase14_obligations.py`'s
//! `crate_module` maps it.
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
//! `src/ssl/methods.rs` and records it as a measured correction to the plan's ordering. The rest of
//! 14.2 stays open.
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
//! SPDX-License-Identifier: Apache-2.0

pub mod methods;
pub mod ssl_lib;
