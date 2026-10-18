//! Phase 3 core runtime.
//!
//! The substrate every later subsystem stands on: allocation, the error queue,
//! and the collection type the public API is built from. These are the first
//! modules whose symbols are **implemented rather than scaffolded**, and they
//! are ordered first deliberately — `docs/RELEASE_GATES.md` §1 puts the runtime
//! before BIO, the object database, and everything cryptographic, because a
//! correct upper layer cannot be built on an incorrect substrate.
//!
//! ## What "implemented" means here
//!
//! A symbol moves out of the ABI shell's scaffold set only when it has:
//!
//! * a real body, not a diagnosed abort;
//! * a differential court against the authority (`RT-MEM`, `RT-ERR`, `RT-STACK`);
//! * the applicable parity dimensions recorded — ABI, semantic, ownership,
//!   error — with unproved dimensions left honestly unproved.
//!
//! The shell generator derives its scaffold set from *this* module tree, so the
//! implementation decides what is implemented; nothing is listed twice.

//! See `docs/RELEASE_GATES.md` §1 for why the runtime is built before everything
//! else, and `docs/PARITY_MODEL.md` for what a symbol must prove before it stops
//! being `SCAFFOLDED`.

pub mod bio;
pub mod bsearch;
pub mod buffer;
pub mod conf;
pub mod confmod;
pub mod constant_time;
pub mod ctype;
pub mod ctype_table;
pub mod defaults;
pub mod dir;
pub mod dso_shared;
pub mod err;
pub mod err_state;
pub mod ex_data;
// Ownership of a foreign `*_new` object the caller's own `*_free` releases. Shared by
// the two `ssl/statem` modules; distinct from `bio::owned::OwnedCtx` (allocator seam).
pub(crate) mod foreign;
pub mod getenv;
pub mod init;
pub mod lhash;
pub mod mem;
// The static-lifetime allocator coordinate a safe owner constructor accepts.
// Keeping the pointer in this one type makes a temporary C-string pointer
// inexpressible through the safe constructors.
pub(crate) mod mem_coords;
// The one shared validated handle over an object-owned C-string member buffer.
pub(crate) mod member_slot;
// Phase 18's Miri-admitted TCB suite. Test-only and Miri-only: `cargo test` does not
// compile it, `cargo +nightly miri test --lib miri_tcb` does. It installs a
// Rust-backed allocator shim so the `CRYPTO_*` ownership and container paths run
// under Miri's strict-provenance model without touching libc. See the module docs.
#[cfg(all(test, miri))]
pub(crate) mod miri_tcb;
// Test-only observation of the release arm and coordinates each owned-block family
// selects, so a silent D1-style drift becomes a failing regression.
pub mod obj;
#[cfg(test)]
pub(crate) mod release_probe;
// The shared owner for the `B-R1a` `{ptr, release}` byte-buffer group. Internal:
// the callers are module-local transcription paths, not the exported ABI.
pub(crate) mod owned_buf;
// The shared owner for the `S-P` `{ptr, file, line}` C-string group. Internal:
// the callers are module-local transcription paths, not the exported ABI.
pub(crate) mod owned_str;
pub mod rcu;
pub mod rdtsc;
// The shared `CRYPTO_REF_COUNT` gate protocol. The destroying sentinel and its
// compare-and-swap live in the object's existing atomic count; see the module docs.
pub(crate) mod refcount;
pub mod secure;
pub mod sparse_array;
// Phase 25.8's differential harness over the sparse array. Test-only tooling: it is a no-op
// unless `SPARSE_ARRAY_PROBE=1` is set, so the ordinary suite never has its process-global
// allocator seam replaced. `forensics/tools/ms_sparse_array_court.py` runs it against the C
// probe's transcript of the authority. See the module docs.
#[cfg(test)]
pub(crate) mod sparse_array_probe;
pub mod stack;
pub mod str;
pub mod thread;
pub mod thread_arch;
pub mod thread_events;
pub mod threads_common;
pub mod time;
pub mod trace;
pub mod uid;
