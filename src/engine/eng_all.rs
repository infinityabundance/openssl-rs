//! Phase 10.9 — `crypto/engine/eng_all.c`: the built-in-engine loader.
//!
//! **Withheld: `ENGINE_load_builtin_engines` (`eng_all.c:13-16`), blocker: the crate's
//! `OPENSSL_init_crypto` refuses the `ENGINE_*` bits.**
//!
//! The function's body is one call, `OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN,
//! NULL)`. In the authority that call dispatches to the per-engine `ossl_init_engine_*`
//! steps and registers whatever built-in engines the build carries; in this crate those
//! bits are on `INIT_UNSUPPORTED` (`src/runtime/init.rs:254-261`) and the call **raises and
//! returns 0**. Transcribing the body would therefore land a function whose observable
//! behaviour differs from the authority's on every call, which is exactly the wrong answer
//! under `docs/SECURITY_DIVERGENCE_POLICY.md`: the arm is withheld until the init sequence
//! honours the `ENGINE_*` bits, rather than answered with a call the crate refuses.
//!
//! Withholding this function is also what withholds `ENGINE_by_id` (`eng_list.rs`): its
//! first act is a call to this loader, so the two land together or the miss path is not
//! honest.
//!
//! `ENGINE_setup_bsd_cryptodev` (`:20-23`) is not in the admitted build — it is guarded by
//! `__OpenBSD__`/`__FreeBSD__`/`__DragonFly__` — so there is nothing to transcribe for it.
//!
//! SPDX-License-Identifier: Apache-2.0

// This unit defines no Rust item: the one function of `eng_all.c` that the admitted build
// compiles is withheld, with its blocker, in the module documentation above.
