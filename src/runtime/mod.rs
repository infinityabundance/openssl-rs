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
pub mod ctype;
pub mod ctype_table;
pub mod dir;
pub mod err;
pub mod err_state;
pub mod ex_data;
pub mod getenv;
pub mod init;
pub mod lhash;
pub mod mem;
pub mod obj;
pub mod secure;
pub mod stack;
pub mod str;
pub mod thread;
pub mod time;
pub mod trace;
pub mod uid;
