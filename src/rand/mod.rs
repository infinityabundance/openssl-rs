//! Phase 9 — `crypto/rand/`.
//!
//! The random layer's own translation units, as opposed to the EVP `EVP_RAND_*` front that lives in
//! `src/evp/rand.rs` (Phase 7's `evp_rand.c`, which is imported here rather than duplicated) and
//! the provider implementations that live in `src/provider/`.
//!
//! The layout is `docs/PHASE-9-SUBPHASES.md`'s:
//!
//! * [`pool`] — `crypto/rand/rand_pool.c`. **Landed**, with no caller yet; the module says why.
//! * `rand_lib.c`'s twenty-five exports — 9.2, not started.
//! * `randfile.c` — reached only from `rand_lib.c`'s file helpers, 9.2.
//!
//! The unit that is *not* here is `providers/implementations/rands/seeding/rand_unix.c`, which
//! holds `ossl_pool_acquire_entropy` and `ossl_rand_pool_init`/`_cleanup`. It belongs to the
//! provider side and to 9.5, and the two corrections that placed it there are D298's.
//!
//! SPDX-License-Identifier: Apache-2.0

pub(crate) mod pool;
pub(crate) mod sys;
