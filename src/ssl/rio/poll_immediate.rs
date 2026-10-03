//! Phase 14.4 — `ssl/rio/poll_immediate.c`: the non-QUIC `SSL_poll`.
//!
//! The authority's `SSL_poll` is a small readout loop over an item array, with a blocking arm that
//! only a QUIC object reaches. This slice lands the readout and the item dispatch, which is the
//! whole of what a non-QUIC caller can observe.
//!
//! ## What landed
//!
//! * `SSL_poll` — the trivial zero-item case, the per-item readout, and the three refusal arms
//!   (a non-QUIC SSL descriptor, a socket descriptor and an unknown descriptor type), each of which
//!   marks `SSL_POLL_EVENT_F` on the offending item and returns 0.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The QUIC arms are not implemented, and cannot be reached.** `poll_readout`'s
//!   `SSL_TYPE_QUIC_*` cases call `ossl_quic_conn_poll_events` (`poll_immediate.c:397`); the QUIC
//!   object model is Phase 15's and no object this crate builds has a QUIC type, so every non-NULL
//!   SSL descriptor takes the `default` arm, which is the authority's own answer for it.
//! * **The zero-item arm does not sleep.** The authority calls `OSSL_sleep` for a NULL timeout with
//!   no items (`poll_immediate.c:451-453`); sleeping moves no observation and this slice omits the
//!   wall-clock call. The court drives the zero-item arm with a NULL or zero timeout only.
//! * **The blocking path is not implemented.** It is reachable only for a QUIC object with no ready
//!   event (`poll_immediate.c:488-493`), which this crate cannot construct.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};

use crate::runtime::bio::{
    BioPollDescriptor, BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD, BIO_POLL_DESCRIPTOR_TYPE_SSL,
};
use crate::runtime::err::err_reasons::SSL_R_POLL_REQUEST_NOT_SUPPORTED;
use crate::runtime::err::raise_with;
use crate::ssl::ssl_lib::{Ssl, Timeval};

/// `ERR_LIB_SSL` — `include/openssl/err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `OPENSSL_FILE` of this translation unit, used on the raise sites.
const FILE: *const c_char = c"ssl/rio/poll_immediate.c".as_ptr();
/// `SSL_POLL_EVENT_F` — `ssl.h:2552`.
const SSL_POLL_EVENT_F: u64 = 1;

/// `SSL_POLL_ITEM` — `ssl.h:2578-2581`.
#[repr(C)]
pub struct SslPollItem {
    /// `BIO_POLL_DESCRIPTOR desc`.
    pub desc: BioPollDescriptor,
    /// `uint64_t events`.
    pub events: u64,
    /// `uint64_t revents`.
    pub revents: u64,
}

/// `int SSL_poll(SSL_POLL_ITEM *items, size_t num_items, size_t stride,
/// const struct timeval *timeout, uint64_t flags, size_t *p_result_count)` —
/// `ssl/rio/poll_immediate.c:437-503`.
///
/// # Safety
/// `items` must be readable for `num_items` records stepped by `stride`; `timeout` NULL or live;
/// `p_result_count` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_poll(
    items: *mut SslPollItem,
    num_items: usize,
    stride: usize,
    timeout: *const Timeval,
    flags: u64,
    p_result_count: *mut usize,
) -> c_int {
    // `do_tick` and the deadline conversion are unobservable here; the only arm that would use
    // them is the QUIC blocking path, which is not reachable.
    let _ = (flags, timeout);

    let mut result_count: usize = 0;
    if num_items == 0 {
        if !p_result_count.is_null() {
            // SAFETY: `p_result_count` is writable per the contract.
            unsafe { *p_result_count = result_count };
        }
        return 1;
    }

    let mut ok: c_int = 1;
    let mut i: usize = 0;
    while i < num_items {
        // SAFETY: `items` is readable for `num_items` records stepped by `stride` per the contract,
        // so the `i`-th record is in range.
        let item = unsafe { items.cast::<u8>().add(i * stride).cast::<SslPollItem>() };
        // SAFETY: `item` points at a live record.
        match unsafe { (*item).desc.r#type } {
            BIO_POLL_DESCRIPTOR_TYPE_SSL => {
                // SAFETY: `item` is live; the union's `ssl` member is the active one.
                let ssl = unsafe { (*item).desc.value.ssl } as *const Ssl;
                if ssl.is_null() {
                    // NULL items are no-ops and have `revents` reported as 0.
                    // SAFETY: `item` is live.
                    unsafe { (*item).revents = 0 };
                } else {
                    // The `default` arm: a non-QUIC SSL object is refused.
                    // SAFETY: a constant site.
                    unsafe { raise_with(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED, FILE, 262) };
                    // SAFETY: `item` is live.
                    unsafe { (*item).revents = SSL_POLL_EVENT_F };
                    result_count += 1;
                    // SAFETY: `items` is readable for `num_items` records stepped by `stride`.
                    unsafe { fail_from(items, num_items, stride, i + 1) };
                    ok = 0;
                    break;
                }
            }
            BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD => {
                // SAFETY: a constant site.
                unsafe { raise_with(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED, FILE, 270) };
                // SAFETY: `item` is live.
                unsafe { (*item).revents = SSL_POLL_EVENT_F };
                result_count += 1;
                // SAFETY: `items` is readable for `num_items` records stepped by `stride`.
                unsafe { fail_from(items, num_items, stride, i + 1) };
                ok = 0;
                break;
            }
            _ => {
                // SAFETY: a constant site.
                unsafe { raise_with(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED, FILE, 276) };
                // SAFETY: `item` is live.
                unsafe { (*item).revents = SSL_POLL_EVENT_F };
                result_count += 1;
                // SAFETY: `items` is readable for `num_items` records stepped by `stride`.
                unsafe { fail_from(items, num_items, stride, i + 1) };
                ok = 0;
                break;
            }
        }
        i += 1;
    }

    if !p_result_count.is_null() {
        // SAFETY: `p_result_count` is writable per the contract.
        unsafe { *p_result_count = result_count };
    }
    ok
}

/// `FAIL_FROM(n)` — zero the `revents` of items `n..num_items`.
///
/// # Safety
/// `items` must be readable for `num_items` records stepped by `stride`.
unsafe fn fail_from(items: *mut SslPollItem, num_items: usize, stride: usize, n: usize) {
    let mut j = n;
    while j < num_items {
        // SAFETY: as in `SSL_poll`, the `j`-th record is in range.
        let item = unsafe { items.cast::<u8>().add(j * stride).cast::<SslPollItem>() };
        // SAFETY: `item` points at a live record.
        unsafe { (*item).revents = 0 };
        j += 1;
    }
}
