//! Phase 7.4 — the `EVP_PKEY` layer: its context, its methods and the ASN.1 glue declared in
//! `evp.h`.
//!
//! This module is 7.4's and is otherwise **unwritten**. What is here is the one thing 7.3d-ii
//! could not leave out, and the reason is a struct member rather than a function of this stratum.
//!
//! ## Why a shell exists before the stratum does
//!
//! `struct evp_md_ctx_st` — the digest context, transcribed by 7.3d-ii — carries an
//! `EVP_PKEY_CTX *pctx`, and `crypto/evp/digest.c` touches it in exactly three places:
//! `evp_md_ctx_reset_ex` releases it, `EVP_MD_CTX_set_pkey_ctx` releases the previous one and
//! stores the new one, and `EVP_MD_CTX_copy_ex` duplicates it. So the digest stratum needs two
//! operations on an `EVP_PKEY_CTX` — **release** and **duplicate** — and nothing else.
//!
//! Transcribing `struct evp_pkey_ctx_st` to get them would drag one hundred and forty-one
//! obligations into a subphase that cannot court any of them. Instead this module declares the
//! type **opaquely** and gives the two operations the internal spellings the digest stratum calls.
//! When 7.4 lands, `EVP_PKEY_CTX_free` and `EVP_PKEY_CTX_dup` become thin wrappers over the two
//! functions below rather than a second, divergent, implementation — the same relationship
//! `evp_md_get_number` has to `EVP_MD_get_number`.
//!
//! ## The two operations refuse what they cannot release
//!
//! Every `EVP_PKEY_CTX` constructor — `EVP_PKEY_CTX_new`, `EVP_PKEY_CTX_new_from_pkey`, the
//! `EVP_PKEY_CTX_new_id` family — is 7.4's and is a scaffold today. A scaffold **aborts** rather
//! than returning a plausible value (`src/lib.rs`), so no caller of this crate, including every
//! court, can hold a non-NULL `EVP_PKEY_CTX`: the only way to obtain one is to manufacture the
//! pointer, and a manufactured pointer is not an `EVP_PKEY_CTX` on either side.
//!
//! That makes the NULL arm the whole of the reachable contract, and it is transcribed exactly: a
//! NULL release does nothing and a NULL duplicate answers NULL, which is what
//! `EVP_PKEY_CTX_free(NULL)` and `EVP_PKEY_CTX_dup(NULL)` do in the authority.
//!
//! The non-NULL arm **aborts with a diagnostic** rather than returning quietly. A quiet return
//! would leak the block it was asked to release, or hand back a second reference to an object it
//! cannot copy, and both of those are wrong answers that no court could see — the failure would be
//! silent. Aborting is the project's rule for a state it cannot serve honestly: it is loud, it is
//! visible in a transcript, and it disappears the moment 7.4 transcribes the struct.
//!
//! SPDX-License-Identifier: Apache-2.0

/// `struct evp_pkey_ctx_st` — `EVP_PKEY_CTX`, opaque until 7.4 transcribes it.
///
/// `pub` for the reason every type appearing in an exported signature is: `EVP_MD_CTX_get_pkey_ctx`
/// and `EVP_MD_CTX_set_pkey_ctx` are exported and name it, and Rust requires the type of an
/// exported item's parameter to be at least as visible. It is zero-sized, so the type carries no
/// layout claim it cannot support — nothing in this crate dereferences one.
#[repr(C)]
pub struct EvpPkeyCtx {
    _private: [u8; 0],
}

/// The diagnostic the non-NULL arm writes before aborting.
const UNSUPPORTED: &[u8] = b"openssl-rs: EVP_PKEY_CTX is not transcribable yet (Phase 7.4); \
      a non-NULL EVP_PKEY_CTX reached the digest context's pctx seam\n";

unsafe extern "C" {
    /// `void abort(void)`, from `<stdlib.h>`.
    fn abort() -> !;
}

/// Write `bytes` to file descriptor 2, once, unbuffered.
///
/// The same shape `src/runtime/init.rs` uses for `OPENSSL_die`: a direct write rather than a
/// `stdio` stream, so the message is not lost when the process dies immediately afterwards.
fn write_all_fd2(bytes: &[u8]) {
    use std::io::Write;

    let mut err = std::io::stderr();
    // The result is discarded deliberately: there is nothing to do about a failed write on the
    // way to an abort, and a `let _ =` is a write rather than an unwind.
    let _ = err.write_all(bytes);
}

/// `void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx)` — the internal spelling.
///
/// 7.4 exports the authority's name; this is what `crypto/evp/digest.c` calls, from
/// `evp_md_ctx_reset_ex` and `EVP_MD_CTX_set_pkey_ctx`.
///
/// # Safety
/// `pctx` must be NULL or a live `EVP_PKEY_CTX`. A NULL is the only value reachable in this crate
/// today; see the module documentation.
pub(crate) unsafe fn evp_pkey_ctx_free(pctx: *mut EvpPkeyCtx) {
    if pctx.is_null() {
        return;
    }
    write_all_fd2(UNSUPPORTED);
    // SAFETY: `abort` has no preconditions and does not return, so nothing after this line runs.
    unsafe { abort() }
}

/// `EVP_PKEY_CTX *EVP_PKEY_CTX_dup(EVP_PKEY_CTX *ctx)` — the internal spelling.
///
/// The authority's `EVP_PKEY_CTX_dup` answers **NULL for a NULL context**, which
/// `EVP_MD_CTX_copy_ex` relies on: the caller tests `in->pctx` first, but the duplicate is what
/// decides the reference count.
///
/// # Safety
/// `pctx` must be NULL or a live `EVP_PKEY_CTX`; the answer, if non-NULL, is owned by the caller.
pub(crate) unsafe fn evp_pkey_ctx_dup(pctx: *mut EvpPkeyCtx) -> *mut EvpPkeyCtx {
    if pctx.is_null() {
        return core::ptr::null_mut();
    }
    write_all_fd2(UNSUPPORTED);
    // SAFETY: `abort` has no preconditions and does not return, so nothing after this line runs.
    unsafe { abort() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The NULL arm is the whole of the reachable contract, and both operations answer the way the
    /// authority's do: nothing to release, and a NULL copy of nothing.
    ///
    /// The non-NULL arm is deliberately **not** tested: it aborts the process, and a test that
    /// killed its own harness would turn a documented seam into a mystery.
    #[test]
    fn null_is_the_whole_of_the_reachable_contract() {
        // SAFETY: NULL is the documented argument for both.
        unsafe {
            evp_pkey_ctx_free(core::ptr::null_mut());
            assert!(
                evp_pkey_ctx_dup(core::ptr::null_mut()).is_null(),
                "a NULL context duplicates to NULL"
            );
        }
    }
}
