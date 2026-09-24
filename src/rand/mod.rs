//! Phase 9 — `crypto/rand/`.
//!
//! The random layer's own translation units, as opposed to the EVP `EVP_RAND_*` front that lives in
//! `src/evp/rand.rs` (Phase 7's `evp_rand.c`, which is imported here rather than duplicated) and
//! the provider implementations that live in `src/provider/`.
//!
//! The layout is `docs/PHASE-9-SUBPHASES.md`'s:
//!
//! * [`pool`] — `crypto/rand/rand_pool.c`. **Landed.**
//! * [`rand_lib`] — `crypto/rand/rand_lib.c`'s **per-context and seed-source half**, which is what
//!   makes slot 5 real and what every DRBG instantiation reads. Its twenty-five `rand.h` exports
//!   are 9.2's remaining work.
//! * [`prov_seed`] — `crypto/rand/prov_seed.c`, the core side of the provider's seeding up-call.
//! * `randfile.c` — reached only from `rand_lib.c`'s file helpers, 9.2.
//!
//! The unit that is *not* here is `providers/implementations/rands/seeding/rand_unix.c`, which
//! holds `ossl_pool_acquire_entropy` and `ossl_rand_pool_init`/`_cleanup`. It belongs to the
//! provider side and to 9.5, and the two corrections that placed it there are D298's.
//!
//! SPDX-License-Identifier: Apache-2.0

pub(crate) mod pool;
pub(crate) mod prov_seed;
pub mod rand_lib;
pub(crate) mod rand_uniform;
pub(crate) mod sys;
pub(crate) mod unix;
