//! Phase 13.7 — `crypto/async/`: the ASYNC job-and-wait framework.
//!
//! `crypto/async/` is three translation units and twenty-two exports:
//!
//! ```text
//! src/async/async.rs             <-  crypto/async/async.c          (8 exports)
//! src/async/async_wait.rs        <-  crypto/async/async_wait.c     (11 exports)
//! src/async/arch/async_posix.rs  <-  crypto/async/arch/async_posix.c (3 exports)
//! ```
//!
//! ## What the framework is
//!
//! An `ASYNC_JOB` is a fibre — a co-routine with its own stack — that a caller starts with
//! [`ASYNC_start_job`]. The job runs until it either returns (the fibre reports
//! `ASYNC_FINISH`) or calls [`ASYNC_pause_job`] (the fibre reports `ASYNC_PAUSE` and yields to
//! the caller). The caller resumes it by calling [`ASYNC_start_job`] again with the job
//! handle the previous call wrote back. `ASYNC_WAIT_CTX`, in [`async_wait`], is the
//! file-descriptor-and-callback state an asynchronous engine uses across a pause, and every
//! `ASYNC_WAIT_CTX_*` name is in `async_wait.c`.
//!
//! ## The platform half, and why a C shim carries it
//!
//! The authority builds its fibres on `ucontext_t` (`crypto/async/arch/async_posix.h`): it
//! reads and writes `uc_stack.ss_sp`, `uc_stack.ss_size` and `uc_link`, and switches stacks
//! with `getcontext`/`makecontext`/`swapcontext`. `ucontext_t`'s layout is the platform's
//! business, so — exactly as `src/runtime/dir_posix.c` reads `struct dirent` and `struct
//! stat` — those operations are made on the C side of the ABI by
//! `src/async/arch/async_ucontext.c`, and only the operations cross into
//! [`arch::async_posix`]. Every behavioural decision stays in Rust: the stack size, the
//! substitutable allocators [`arch::async_posix::ASYNC_set_mem_functions`] installs, and
//! the escalation on a failed switch.
//!
//! ## The init bit this framework needs, and where it is enabled
//!
//! `OPENSSL_INIT_ASYNC` was on `src/runtime/init.rs`'s `INIT_UNSUPPORTED` list while
//! `crypto/async` had no home. The authority's `ossl_init_async` runs `async_init()`, and
//! `ossl_init_async` is what every `ASYNC_*` entry point reaches through
//! `OPENSSL_init_crypto(OPENSSL_INIT_ASYNC, NULL)`, so landing this stratum retires the bit
//! from that list and adds the step at the authority's own position (`crypto/init.c`): after
//! the configuration step, before the engine steps. [`job::async_init`] and
//! [`job::async_deinit`] are the internal pair `init.c`'s run-once and cleanup call.
//!
//! SPDX-License-Identifier: Apache-2.0

/// `crypto/async/arch/` — the platform fibre backend the framework builds on.
pub mod arch {
    /// `crypto/async/arch/async_posix.c` — the POSIX `ucontext_t` fibre backend.
    pub mod async_posix;
}

/// `crypto/async/async_wait.c` — the `ASYNC_WAIT_CTX` object.
pub mod async_wait;

/// `crypto/async/async.c` — the job, the pool and the `ASYNC_*` entry points.
///
/// The module is named `job` rather than `async` because `async` is a Rust keyword; the file
/// it transcribes is `src/async/async.rs`, and the `#[path]` keeps that name on disk where the
/// authority's unit layout puts it.
#[path = "async.rs"]
pub mod job;
