//! Phase 4 — the in-memory datagram pair (`BIO_s_dgram_pair`) and its
//! single-ended sibling (`BIO_s_dgram_mem`), plus `BIO_new_bio_dgram_pair`.
//!
//! Where `BIO_s_bio` is a byte stream, this pair preserves **datagram framing**:
//! each write pushes one header plus one payload into the writer's ring buffer,
//! and each read pops exactly one datagram from the *peer's* ring buffer. Almost
//! every observable behaviour follows from that framing rather than from the
//! bytes:
//!
//! * `BIO_CTRL_PENDING` reports the length of the **next datagram**, because the
//!   control peeks the header rather than counting buffered bytes;
//! * a read with a smaller buffer than the datagram returns the truncated prefix
//!   and **discards the remainder** — unless `BIO_CTRL_DGRAM_SET_NO_TRUNC` is
//!   set, in which case the read fails, restores the ring buffer's cursor and
//!   consumes nothing;
//! * a write that cannot fit the header and the whole payload is **rolled back**,
//!   so a reader never sees half a datagram;
//! * `BIO_CTRL_DGRAM_GET_WRITE_GUARANTEE` reports **zero**, not a small number,
//!   when the free space could not hold a worst-case datagram, because a partial
//!   write is never a datagram;
//! * `BIO_ctrl(GET_EFFECTIVE_CAPS)` answers the *peer's* capabilities on a pair
//!   and its own on a `dgram_mem`, because only `dgram_pair_ctrl` intercepts it.
//!
//! ## The internal header size is observable
//!
//! `dgram_hdr` is internal, but `BIO_CTRL_GET_WRITE_BUF_SIZE` on a fresh BIO
//! reports `9 * (sizeof(hdr) + mtu)`, and the write guarantee reports
//! `size - count - sizeof(hdr)`. Both were measured against the authority
//! (`15336` and `15104` with the default 1472-byte MTU), which fixes
//! `sizeof(hdr)` at **232**: a `size_t` length plus two `BIO_ADDR` values of 112
//! bytes each. The addresses are stored as raw 112-byte slots rather than as
//! [`BioAddr`] values so the size cannot drift with ours.
//!
//! ## Locks
//!
//! The authority takes the peer's lock for reads and its own for writes, with a
//! role field fixing the acquisition order when both are needed. The same
//! structure is reproduced, including that `BIO_read` takes both because it
//! touches the local retry flags while `BIO_recvmmsg` takes one.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{
    BSS_DGRAM_PAIR_1018, BSS_DGRAM_PAIR_1023, BSS_DGRAM_PAIR_1035, BSS_DGRAM_PAIR_1042,
    BSS_DGRAM_PAIR_1070, BSS_DGRAM_PAIR_1081, BSS_DGRAM_PAIR_1095, BSS_DGRAM_PAIR_1120,
    BSS_DGRAM_PAIR_1125, BSS_DGRAM_PAIR_1132, BSS_DGRAM_PAIR_1283, BSS_DGRAM_PAIR_1288,
    BSS_DGRAM_PAIR_1294, BSS_DGRAM_PAIR_1321, BSS_DGRAM_PAIR_1335, BSS_DGRAM_PAIR_309,
    BSS_DGRAM_PAIR_345, BSS_DGRAM_PAIR_351, BSS_DGRAM_PAIR_360, BSS_DGRAM_PAIR_369,
    BSS_DGRAM_PAIR_376, BSS_DGRAM_PAIR_382, BSS_DGRAM_PAIR_388, BSS_DGRAM_PAIR_465,
};
use crate::runtime::err::{raise_site, raise_site_data, raise_site_dynamic};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_realloc, CRYPTO_zalloc};
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoRwlock,
};

use super::addr::{BIO_ADDR_free, BioAddr};
use super::method::{bread_conv, bwrite_conv};
use super::{
    Bio, BioMethod, BioMsg, BIO_CTRL_DGRAM_GET_CAPS, BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS,
    BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP, BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE,
    BIO_CTRL_DGRAM_GET_MTU, BIO_CTRL_DGRAM_GET_NO_TRUNC, BIO_CTRL_DGRAM_SET0_LOCAL_ADDR,
    BIO_CTRL_DGRAM_SET_CAPS, BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE, BIO_CTRL_DGRAM_SET_MTU,
    BIO_CTRL_DGRAM_SET_NO_TRUNC, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_PENDING, BIO_CTRL_RESET,
    BIO_C_DESTROY_BIO_PAIR, BIO_C_GET_WRITE_BUF_SIZE, BIO_C_GET_WRITE_GUARANTEE,
    BIO_C_MAKE_BIO_PAIR, BIO_C_SET_WRITE_BUF_SIZE, BIO_DGRAM_CAP_HANDLES_DST_ADDR,
    BIO_DGRAM_CAP_HANDLES_SRC_ADDR, BIO_DGRAM_CAP_PROVIDES_DST_ADDR, BIO_FLAGS_READ, BIO_FLAGS_RWS,
    BIO_FLAGS_SHOULD_RETRY, BIO_FLAGS_WRITE, BIO_R_BROKEN_PIPE, BIO_R_INVALID_ARGUMENT,
    BIO_R_LOCAL_ADDR_NOT_AVAILABLE, BIO_R_NON_FATAL, BIO_R_PEER_ADDR_NOT_AVAILABLE,
    BIO_R_TRANSFER_ERROR, BIO_R_UNINITIALIZED, BIO_TYPE_DGRAM_MEM, BIO_TYPE_DGRAM_PAIR,
};

/// The authority's `MIN_BUF_LEN`.
const MIN_BUF_LEN: usize = 1024;

/// The default MTU a fresh context starts with.
const DEFAULT_MTU: usize = 1472;

/// The size of one `BIO_ADDR` as it appears inside [`DgramHdr`].
///
/// Measured, not assumed: `BIO_CTRL_GET_WRITE_BUF_SIZE` on a fresh BIO is
/// `9 * (sizeof(hdr) + 1472) = 15336`, so `sizeof(hdr) = 232` and each address
/// slot is `(232 - 8) / 2 = 112` bytes — the authority's `union bio_addr_st`
/// (a `sockaddr_un`, 110 bytes, rounded to 4-byte alignment).
const HDR_ADDR_SIZE: usize = 112;

/// The authority's `struct dgram_hdr`.
///
/// Stored as raw slots rather than [`BioAddr`] values so this size is fixed by
/// the measured constant above.
#[repr(C)]
struct DgramHdr {
    /// Payload length in bytes, not including this header.
    len: usize,
    /// Source address, or all-zero when not present.
    src_addr: [u8; HDR_ADDR_SIZE],
    /// Destination address, or all-zero when not present.
    dst_addr: [u8; HDR_ADDR_SIZE],
}

/// The authority's `struct ring_buf`.
#[repr(C)]
struct RingBuf {
    /// The allocation.
    start: *mut u8,
    /// Its size in bytes.
    len: usize,
    /// Bytes currently pushed.
    count: usize,
    /// `[head, tail]`, each an index into `start`.
    idx: [usize; 2],
}

impl RingBuf {
    /// `ring_buf_init`
    fn init(&mut self, nbytes: usize) -> bool {
        // SAFETY: `CRYPTO_malloc` returns a fresh allocation of `nbytes`.
        let p = CRYPTO_malloc(nbytes, ptr::null(), 0).cast::<u8>();
        if p.is_null() {
            return false;
        }
        self.start = p;
        self.len = nbytes;
        self.idx = [0, 0];
        self.count = 0;
        true
    }

    /// `ring_buf_destroy`
    fn destroy(&mut self) {
        if !self.start.is_null() {
            // SAFETY: `start` is owned here.
            unsafe { CRYPTO_free(self.start.cast(), ptr::null(), 0) };
        }
        self.start = ptr::null_mut();
        self.len = 0;
        self.count = 0;
    }

    /// `ring_buf_head_tail` — a pointer into the buffer and how much may be
    /// read/written there without wrapping.
    ///
    /// # Safety
    /// `self.start` must be a live allocation of `self.len` bytes.
    unsafe fn head_tail(&self, idx: usize) -> (*mut u8, usize) {
        let mut max_len = self.len - self.idx[idx];
        if idx == 0 && max_len > self.len - self.count {
            max_len = self.len - self.count;
        }
        if idx == 1 && max_len > self.count {
            max_len = self.count;
        }
        // SAFETY: `idx[idx] <= len`, so the offset stays inside.
        (unsafe { self.start.add(self.idx[idx]) }, max_len)
    }

    /// `ring_buf_push_pop`
    fn push_pop(&mut self, idx: usize, num_bytes: usize) {
        let mut new_idx = self.idx[idx] + num_bytes;
        if new_idx == self.len {
            new_idx = 0;
        }
        self.idx[idx] = new_idx;
        if idx != 0 {
            self.count -= num_bytes;
        } else {
            self.count += num_bytes;
        }
    }

    /// `ring_buf_clear`
    fn clear(&mut self) {
        self.idx = [0, 0];
        self.count = 0;
    }

    /// `ring_buf_resize`
    fn resize(&mut self, nbytes: usize) -> bool {
        if self.start.is_null() {
            return self.init(nbytes);
        }
        if nbytes == self.len {
            return true;
        }
        if self.count > 0 && nbytes < self.len {
            // Shrinking a non-empty ring is refused.
            return false;
        }
        // SAFETY: `start` is owned here and `nbytes` is the new size.
        let new_start =
            unsafe { CRYPTO_realloc(self.start.cast(), nbytes, ptr::null(), 0) }.cast::<u8>();
        if new_start.is_null() {
            return false;
        }
        if self.count > 0 {
            if self.idx[0] <= self.idx[1] {
                let offset = nbytes - self.len;
                // SAFETY: the tail region moves up by `offset` inside the enlarged
                // allocation, which is why `offset` is derived from the growth.
                unsafe {
                    ptr::copy(
                        new_start.add(self.idx[1]),
                        new_start.add(self.idx[1] + offset),
                        self.len - self.idx[1],
                    );
                }
                self.idx[1] += offset;
            }
        } else {
            // The indices may point outside the new allocation.
            self.idx = [0, 0];
        }
        self.start = new_start;
        self.len = nbytes;
        true
    }
}

/// The authority's `struct bio_dgram_pair_st`.
#[repr(C)]
struct BioDgramPairSt {
    /// The other half of the pair, or NULL for `BIO_s_dgram_mem`.
    peer: *mut Bio,
    /// Writes go here; reads come from the peer's.
    rbuf: RingBuf,
    /// The requested ring size, applied on pairing.
    req_buf_len: usize,
    /// Largest possible datagram.
    mtu: usize,
    /// Capability flags.
    cap: u32,
    /// The local address to use, or NULL.
    local_addr: *mut BioAddr,
    /// Protects `rbuf` updates.
    lock: *mut CryptoRwlock,
    /// Reads fail rather than truncate.
    no_trunc: bool,
    /// `BIO_MSG::local` may be used.
    local_addr_enable: bool,
    /// Fixes the lock acquisition order for a pair.
    role: bool,
    /// Set for `BIO_s_dgram_mem` only.
    grows_on_write: bool,
}

/// The method name the authority reports for the pair half.
const PAIR_NAME: &[u8] = b"BIO dgram pair\0";
/// The method name the authority reports for the memory BIO.
const MEM_NAME: &[u8] = b"BIO dgram mem\0";

/// A compiled-in method table. `BIO_s_dgram_pair()` returns its address.
static DGRAM_PAIR_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_DGRAM_PAIR,
    name: PAIR_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(dgram_pair_write),
    bread: Some(bread_conv),
    bread_old: Some(dgram_pair_read),
    bputs: None,
    bgets: None,
    ctrl: Some(dgram_pair_ctrl),
    create: Some(dgram_pair_init),
    destroy: Some(dgram_pair_free),
    callback_ctrl: None,
    sendmmsg: Some(dgram_pair_sendmmsg),
    recvmmsg: Some(dgram_pair_recvmmsg),
};

/// A compiled-in method table. `BIO_s_dgram_mem()` returns its address.
static DGRAM_MEM_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_DGRAM_MEM,
    name: MEM_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(dgram_pair_write),
    bread: Some(bread_conv),
    bread_old: Some(dgram_mem_read),
    bputs: None,
    bgets: None,
    ctrl: Some(dgram_mem_ctrl),
    create: Some(dgram_mem_init),
    destroy: Some(dgram_pair_free),
    callback_ctrl: None,
    sendmmsg: Some(dgram_pair_sendmmsg),
    recvmmsg: Some(dgram_pair_recvmmsg),
};

/// `const BIO_METHOD *BIO_s_dgram_pair(void)`
#[no_mangle]
pub extern "C" fn BIO_s_dgram_pair() -> *const BioMethod {
    guard_ffi(ptr::null(), || &DGRAM_PAIR_METHOD)
}

/// `const BIO_METHOD *BIO_s_dgram_mem(void)`
#[no_mangle]
pub extern "C" fn BIO_s_dgram_mem() -> *const BioMethod {
    guard_ffi(ptr::null(), || &DGRAM_MEM_METHOD)
}

/// This BIO's context.
///
/// # Safety
/// `bio` must be a live BIO created from one of these two methods.
unsafe fn ctx(bio: *mut Bio) -> *mut BioDgramPairSt {
    // SAFETY: the caller guarantees the BIO came from this module.
    unsafe { (*bio).ptr.cast() }
}

/// The peer's context, or NULL when there is no pair.
///
/// # Safety
/// `b` must be a live context.
unsafe fn peer_ctx(b: *mut BioDgramPairSt) -> *mut BioDgramPairSt {
    // SAFETY: `b` is live.
    let peer = unsafe { (*b).peer };
    if peer.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `peer` is a live paired BIO holding a context of this type.
    unsafe { (*peer).ptr.cast() }
}

/// Whether this context has a peer.
///
/// # Safety
/// `b` must be a live context.
unsafe fn is_pair(b: *mut BioDgramPairSt) -> bool {
    // SAFETY: `b` is live.
    unsafe { !(*b).peer.is_null() }
}

/// `dgram_pair_init`
///
/// # Safety
/// `bio` must be a live BIO.
unsafe extern "C" fn dgram_pair_init(bio: *mut Bio) -> c_int {
    // SAFETY: `CRYPTO_zalloc` returns nulled memory of the requested size.
    let b: *mut BioDgramPairSt =
        CRYPTO_zalloc(core::mem::size_of::<BioDgramPairSt>(), ptr::null(), 0).cast();
    if b.is_null() {
        return 0;
    }
    // SAFETY: `b` is a fresh allocation.
    unsafe {
        (*b).mtu = DEFAULT_MTU;
        (*b).req_buf_len = 9 * (core::mem::size_of::<DgramHdr>() + (*b).mtu);
        (*b).lock = CRYPTO_THREAD_lock_new();
        if (*b).lock.is_null() {
            CRYPTO_free(b.cast(), ptr::null(), 0);
            return 0;
        }
        (*bio).ptr = b.cast();
    }
    1
}

/// `dgram_mem_init` — the pair initialiser plus an immediate ring allocation.
///
/// # Safety
/// `bio` must be a live BIO.
unsafe extern "C" fn dgram_mem_init(bio: *mut Bio) -> c_int {
    // SAFETY: `bio` is live.
    if unsafe { dgram_pair_init(bio) } == 0 {
        return 0;
    }
    // SAFETY: `bio` is live and holds a fresh context.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is live.
    unsafe {
        if !(*b).rbuf.init((*b).req_buf_len) {
            dgram_pair_free(bio);
            raise_site(&BSS_DGRAM_PAIR_309);
            return 0;
        }
        (*b).grows_on_write = true;
        (*bio).init = 1;
    }
    1
}

/// `dgram_pair_free` — unpairs first, then releases the lock and the context.
///
/// # Safety
/// `bio` must be NULL or a live BIO created from one of these methods.
unsafe extern "C" fn dgram_pair_free(bio: *mut Bio) -> c_int {
    if bio.is_null() {
        return 0;
    }
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    if b.is_null() {
        return 0;
    }
    // SAFETY: `bio` is live and holds this context type.
    unsafe { dgram_pair_ctrl_destroy_bio_pair(bio) };
    // SAFETY: `b` is live and owns its lock.
    unsafe {
        CRYPTO_THREAD_lock_free((*b).lock);
        CRYPTO_free(b.cast(), ptr::null(), 0);
    }
    1
}

/// `dgram_pair_ctrl_make_bio_pair`
///
/// # Safety
/// `bio1`/`bio2` must be live BIOs created from `BIO_s_dgram_pair`.
unsafe fn dgram_pair_ctrl_make_bio_pair(bio1: *mut Bio, bio2: *mut Bio) -> c_int {
    if bio1.is_null() || bio2.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_DGRAM_PAIR_345) };
        return 0;
    }
    // SAFETY: both are live.
    let (m1, m2) = unsafe { ((*bio1).method, (*bio2).method) };
    // `ptr::eq` on the two method pointers keeps this a pure address comparison;
    // the explicit `&DGRAM_PAIR_METHOD` borrow is the same address the methods
    // table holds, so equality here means "created by BIO_s_dgram_pair".
    if !ptr::eq(m1, &DGRAM_PAIR_METHOD) || !ptr::eq(m2, &DGRAM_PAIR_METHOD) {
        // SAFETY: the site and message are compile-time constants.
        unsafe {
            raise_site_data(
                &BSS_DGRAM_PAIR_351,
                c"both BIOs must be BIO_dgram_pair".as_ptr(),
            )
        };
        return 0;
    }
    // SAFETY: both are live and hold this context type.
    let (b1, b2) = unsafe { (ctx(bio1), ctx(bio2)) };
    if b1.is_null() || b2.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_DGRAM_PAIR_360) };
        return 0;
    }
    // SAFETY: `b1`/`b2` are live.
    if unsafe { !(*b1).peer.is_null() || !(*b2).peer.is_null() } {
        // SAFETY: the site and message are compile-time constants.
        unsafe {
            raise_site_data(
                &BSS_DGRAM_PAIR_369,
                c"cannot associate a BIO_dgram_pair which is already in use".as_ptr(),
            )
        };
        return 0;
    }
    // SAFETY: `b1`/`b2` are live.
    if unsafe { (*b1).req_buf_len < MIN_BUF_LEN || (*b2).req_buf_len < MIN_BUF_LEN } {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_DGRAM_PAIR_376) };
        return 0;
    }
    // SAFETY: `b1` is live.
    if unsafe { (*b1).rbuf.len != (*b1).req_buf_len } {
        // SAFETY: `b1` is live.
        let ok = unsafe { (*b1).rbuf.init((*b1).req_buf_len) };
        if !ok {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BSS_DGRAM_PAIR_382) };
            return 0;
        }
    }
    // SAFETY: `b2` is live.
    if unsafe { (*b2).rbuf.len != (*b2).req_buf_len } {
        // SAFETY: `b2` is live.
        let ok = unsafe { (*b2).rbuf.init((*b2).req_buf_len) };
        if !ok {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_site(&BSS_DGRAM_PAIR_388);
                (*b1).rbuf.destroy();
            }
            return 0;
        }
    }
    // SAFETY: all pointers are live.
    unsafe {
        (*b1).peer = bio2;
        (*b2).peer = bio1;
        (*b1).role = false;
        (*b2).role = true;
        (*bio1).init = 1;
        (*bio2).init = 1;
    }
    1
}

/// `dgram_pair_ctrl_destroy_bio_pair`
///
/// # Safety
/// `bio1` must be a live BIO created from one of these methods.
unsafe fn dgram_pair_ctrl_destroy_bio_pair(bio1: *mut Bio) -> c_int {
    // SAFETY: `bio1` is live.
    let b1 = unsafe { ctx(bio1) };
    if b1.is_null() {
        return 1;
    }
    // SAFETY: `b1` is live.
    unsafe {
        (*b1).rbuf.destroy();
        (*bio1).init = 0;
        if !(*b1).local_addr.is_null() {
            BIO_ADDR_free((*b1).local_addr);
            (*b1).local_addr = ptr::null_mut();
        }
        if (*b1).peer.is_null() {
            return 1;
        }
    }
    // SAFETY: `b1` is live and paired.
    let bio2 = unsafe { (*b1).peer };
    // SAFETY: `bio2` is live and holds this context type.
    let b2 = unsafe { ctx(bio2) };
    // SAFETY: all live.
    unsafe {
        (*b2).rbuf.destroy();
        (*bio2).init = 0;
        (*b1).peer = ptr::null_mut();
        (*b2).peer = ptr::null_mut();
    }
    1
}

/// `dgram_pair_ctrl_eof`
///
/// # Safety
/// `bio` must be a live BIO created from one of these methods.
unsafe fn dgram_pair_ctrl_eof(bio: *mut Bio) -> c_int {
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    if b.is_null() {
        return -1;
    }
    // SAFETY: `bio` is live.
    if unsafe { (*bio).init } == 0 {
        // Never initialised means nothing can ever be read.
        return 1;
    }
    // SAFETY: `b` is live.
    if !unsafe { is_pair(b) } {
        return 0;
    }
    // Datagram semantics: with a peer there is never an end of file.
    0
}

/// `dgram_pair_ctrl_set_write_buf_size`
///
/// # Safety
/// `bio` must be a live BIO created from one of these methods.
unsafe fn dgram_pair_ctrl_set_write_buf_size(bio: *mut Bio, mut len: usize) -> c_int {
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is live.
    if unsafe { !(*b).peer.is_null() } {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_DGRAM_PAIR_465) };
        return 0;
    }
    if len < MIN_BUF_LEN {
        len = MIN_BUF_LEN;
    }
    // SAFETY: `b` is live.
    unsafe {
        if !(*b).rbuf.start.is_null() && !(*b).rbuf.resize(len) {
            return 0;
        }
        (*b).req_buf_len = len;
        (*b).grows_on_write = false;
    }
    1
}

/// `dgram_pair_ctrl_reset`
///
/// # Safety
/// `bio` must be a live BIO created from one of these methods.
unsafe fn dgram_pair_ctrl_reset(bio: *mut Bio) -> c_int {
    // SAFETY: `bio` is live and holds this context type.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is live.
    unsafe { (*b).rbuf.clear() };
    1
}

/// `dgram_pair_read_inner` — pops up to `sz` bytes from `b`'s ring.
///
/// # Safety
/// `b` must be a live context whose `rbuf` is initialised; `buf` must be
/// writable for `sz` bytes or NULL.
unsafe fn dgram_pair_read_inner(b: *mut BioDgramPairSt, buf: *mut u8, mut sz: usize) -> usize {
    let mut total = 0usize;
    while sz > 0 {
        // SAFETY: `b` is live and its ring is initialised.
        let (src, mut src_len) = unsafe { (*b).rbuf.head_tail(1) };
        if src_len == 0 {
            break;
        }
        if src_len > sz {
            src_len = sz;
        }
        if !buf.is_null() {
            // SAFETY: `src` is valid for `src_len` bytes and `buf` for `sz >= src_len`.
            unsafe { ptr::copy_nonoverlapping(src, buf.add(total), src_len) };
        }
        // SAFETY: `b` is live.
        unsafe { (*b).rbuf.push_pop(1, src_len) };
        total += src_len;
        sz -= src_len;
    }
    total
}

/// `dgram_pair_ctrl_pending` — peeks the next datagram's length by reading its
/// header and restoring the cursor.
///
/// # Safety
/// `bio` must be a live BIO created from one of these methods.
unsafe fn dgram_pair_ctrl_pending(bio: *mut Bio) -> usize {
    // SAFETY: `bio` is live.
    if unsafe { (*bio).init } == 0 {
        return 0;
    }
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is live.
    let readb = if unsafe { is_pair(b) } {
        // SAFETY: `b` is live and paired.
        unsafe { peer_ctx(b) }
    } else {
        b
    };
    // SAFETY: `readb` is live.
    if unsafe { CRYPTO_THREAD_write_lock((*readb).lock) } == 0 {
        return 0;
    }
    // SAFETY: `readb` is live and its ring is initialised.
    let (saved_idx, saved_count) = unsafe { ((*readb).rbuf.idx[1], (*readb).rbuf.count) };
    let mut hdr = DgramHdr {
        len: 0,
        src_addr: [0; HDR_ADDR_SIZE],
        dst_addr: [0; HDR_ADDR_SIZE],
    };
    // SAFETY: `readb` is live; `hdr` is writable for its own size.
    let l = unsafe {
        dgram_pair_read_inner(
            readb,
            ptr::addr_of_mut!(hdr).cast::<u8>(),
            core::mem::size_of::<DgramHdr>(),
        )
    };
    // SAFETY: `readb` is live.
    unsafe {
        (*readb).rbuf.idx[1] = saved_idx;
        (*readb).rbuf.count = saved_count;
        CRYPTO_THREAD_unlock((*readb).lock);
    }
    if l == 0 {
        0
    } else {
        hdr.len
    }
}

/// `dgram_pair_ctrl_get_write_guarantee`
///
/// # Safety
/// `bio` must be a live BIO created from one of these methods.
unsafe fn dgram_pair_ctrl_get_write_guarantee(bio: *mut Bio) -> usize {
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is live and owns its lock.
    if unsafe { CRYPTO_THREAD_read_lock((*b).lock) } == 0 {
        return 0;
    }
    // SAFETY: `b` is live.
    let mut l = unsafe { (*b).rbuf.len.saturating_sub((*b).rbuf.count) };
    let hdr = core::mem::size_of::<DgramHdr>();
    if l >= hdr {
        l -= hdr;
    }
    // A partial datagram is not a datagram, so report nothing rather than a
    // number too small to be useful.
    // SAFETY: `b` is live.
    if l < unsafe { (*b).mtu } {
        l = 0;
    }
    // SAFETY: `b` is live.
    unsafe { CRYPTO_THREAD_unlock((*b).lock) };
    l
}

/// `dgram_pair_ctrl_get_local_addr_cap`
///
/// # Safety
/// `bio` must be a live BIO created from one of these methods.
unsafe fn dgram_pair_ctrl_get_local_addr_cap(bio: *mut Bio) -> c_int {
    // SAFETY: `bio` is live.
    if unsafe { (*bio).init } == 0 {
        return 0;
    }
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is live.
    let readb = if unsafe { is_pair(b) } {
        // SAFETY: `b` is live and paired.
        unsafe { peer_ctx(b) }
    } else {
        b
    };
    // SAFETY: `readb` is live.
    let cap = unsafe { (*readb).cap };
    let needed = (BIO_DGRAM_CAP_HANDLES_SRC_ADDR | BIO_DGRAM_CAP_PROVIDES_DST_ADDR) as u32;
    c_int::from((!cap & needed) == 0)
}

/// `dgram_pair_ctrl_get_effective_caps`
///
/// # Safety
/// `bio` must be a live BIO created from one of these methods.
unsafe fn dgram_pair_ctrl_get_effective_caps(bio: *mut Bio) -> c_int {
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is live.
    if unsafe { (*b).peer.is_null() } {
        return 0;
    }
    // SAFETY: `b` is live and paired.
    let peerb = unsafe { peer_ctx(b) };
    // SAFETY: `peerb` is live.
    unsafe { (*peerb).cap as c_int }
}

/// `dgram_pair_ctrl_get_caps`
///
/// # Safety
/// `bio` must be a live BIO created from one of these methods.
unsafe fn dgram_pair_ctrl_get_caps(bio: *mut Bio) -> u32 {
    // SAFETY: `bio` is live.
    unsafe { (*ctx(bio)).cap }
}

/// `dgram_pair_ctrl_set_caps`
///
/// # Safety
/// `bio` must be a live BIO created from one of these methods.
unsafe fn dgram_pair_ctrl_set_caps(bio: *mut Bio, caps: u32) -> c_int {
    // SAFETY: `bio` is live.
    unsafe { (*ctx(bio)).cap = caps };
    1
}

/// `dgram_pair_ctrl_get_local_addr_enable`
///
/// # Safety
/// `bio` must be a live BIO created from one of these methods.
unsafe fn dgram_pair_ctrl_get_local_addr_enable(bio: *mut Bio) -> c_int {
    // SAFETY: `bio` is live.
    c_int::from(unsafe { (*ctx(bio)).local_addr_enable })
}

/// `dgram_pair_ctrl_set_local_addr_enable`
///
/// # Safety
/// `bio` must be a live BIO created from one of these methods.
unsafe fn dgram_pair_ctrl_set_local_addr_enable(bio: *mut Bio, enable: c_int) -> c_int {
    // SAFETY: `bio` is live.
    if unsafe { dgram_pair_ctrl_get_local_addr_cap(bio) } == 0 {
        return 0;
    }
    // SAFETY: `bio` is live.
    unsafe { (*ctx(bio)).local_addr_enable = enable != 0 };
    1
}

/// `dgram_pair_ctrl_get_mtu`
///
/// # Safety
/// `bio` must be a live BIO created from one of these methods.
unsafe fn dgram_pair_ctrl_get_mtu(bio: *mut Bio) -> c_int {
    // SAFETY: `bio` is live.
    unsafe { (*ctx(bio)).mtu as c_int }
}

/// `dgram_pair_ctrl_set_mtu` — the MTU is propagated to the peer.
///
/// # Safety
/// `bio` must be a live BIO created from one of these methods.
unsafe fn dgram_pair_ctrl_set_mtu(bio: *mut Bio, mtu: usize) -> c_int {
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is live.
    unsafe {
        (*b).mtu = mtu;
        if !(*b).peer.is_null() {
            let peerb = peer_ctx(b);
            (*peerb).mtu = mtu;
        }
    }
    1
}

/// `dgram_pair_ctrl_set0_local_addr` — takes ownership of `addr`.
///
/// # Safety
/// `bio` must be a live BIO created from one of these methods and `addr` must be
/// NULL or an address this crate allocated.
unsafe fn dgram_pair_ctrl_set0_local_addr(bio: *mut Bio, addr: *mut BioAddr) -> c_int {
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is live and owns its current local address.
    unsafe {
        if !(*b).local_addr.is_null() {
            BIO_ADDR_free((*b).local_addr);
        }
        (*b).local_addr = addr;
    }
    1
}

/// `dgram_mem_ctrl` — the controls shared by both methods.
///
/// # Safety
/// `bio` must be a live BIO created from one of these methods and `ptr` must
/// match the control's contract.
unsafe extern "C" fn dgram_mem_ctrl(
    bio: *mut Bio,
    cmd: c_int,
    num: c_long,
    ptr_: *mut c_void,
) -> c_long {
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    if b.is_null() {
        return 0;
    }
    let mut ret: c_long = 1;

    match cmd {
        BIO_C_SET_WRITE_BUF_SIZE => {
            // SAFETY: `bio` is live.
            ret = unsafe { dgram_pair_ctrl_set_write_buf_size(bio, num as usize) } as c_long;
        }
        BIO_C_GET_WRITE_BUF_SIZE => {
            // SAFETY: `b` is live.
            ret = unsafe { (*b).req_buf_len } as c_long;
        }
        BIO_CTRL_RESET => {
            // SAFETY: `bio` is live.
            unsafe { dgram_pair_ctrl_reset(bio) };
        }
        BIO_C_GET_WRITE_GUARANTEE => {
            // SAFETY: `bio` is live.
            ret = unsafe { dgram_pair_ctrl_get_write_guarantee(bio) } as c_long;
        }
        BIO_CTRL_PENDING => {
            // SAFETY: `bio` is live.
            ret = unsafe { dgram_pair_ctrl_pending(bio) } as c_long;
        }
        BIO_CTRL_FLUSH => {}
        BIO_CTRL_DGRAM_GET_NO_TRUNC => {
            // SAFETY: `b` is live.
            ret = c_long::from(unsafe { (*b).no_trunc });
        }
        BIO_CTRL_DGRAM_SET_NO_TRUNC => {
            // SAFETY: `b` is live.
            unsafe { (*b).no_trunc = num > 0 };
        }
        BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE => {
            // This one reports through its pointer, and still returns 1.
            // SAFETY: the control's contract says `ptr_` is an `int *`.
            unsafe { *(ptr_ as *mut c_int) = dgram_pair_ctrl_get_local_addr_enable(bio) };
        }
        BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE => {
            // SAFETY: `bio` is live.
            ret = unsafe { dgram_pair_ctrl_set_local_addr_enable(bio, num as c_int) } as c_long;
        }
        BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP => {
            // SAFETY: `bio` is live.
            ret = unsafe { dgram_pair_ctrl_get_local_addr_cap(bio) } as c_long;
        }
        BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS | BIO_CTRL_DGRAM_GET_CAPS => {
            // Both answer this context's own capabilities here; a pair intercepts
            // `GET_EFFECTIVE_CAPS` before it reaches this arm.
            // SAFETY: `bio` is live.
            ret = unsafe { dgram_pair_ctrl_get_caps(bio) } as c_long;
        }
        BIO_CTRL_DGRAM_SET_CAPS => {
            // SAFETY: `bio` is live.
            ret = unsafe { dgram_pair_ctrl_set_caps(bio, num as u32) } as c_long;
        }
        BIO_CTRL_DGRAM_GET_MTU => {
            // SAFETY: `bio` is live.
            ret = unsafe { dgram_pair_ctrl_get_mtu(bio) } as c_long;
        }
        BIO_CTRL_DGRAM_SET_MTU => {
            // SAFETY: `bio` is live.
            ret = unsafe { dgram_pair_ctrl_set_mtu(bio, num as u32 as usize) } as c_long;
        }
        BIO_CTRL_DGRAM_SET0_LOCAL_ADDR => {
            // SAFETY: `bio` is live and `ptr_` is the address to take.
            ret = unsafe { dgram_pair_ctrl_set0_local_addr(bio, ptr_.cast()) } as c_long;
        }
        BIO_CTRL_EOF => {
            // SAFETY: `bio` is live.
            ret = unsafe { dgram_pair_ctrl_eof(bio) } as c_long;
        }
        _ => {
            ret = 0;
        }
    }
    ret
}

/// The address slots in [`DgramHdr`] must not be wider than a [`BioAddr`].
const _: () = assert!(core::mem::size_of::<BioAddr>() >= HDR_ADDR_SIZE);

/// `dgram_pair_ctrl` — the pair's controls, falling back to the shared set.
///
/// # Safety
/// `bio` must be a live BIO created from `BIO_s_dgram_pair` and `ptr` must match
/// the control's contract.
unsafe extern "C" fn dgram_pair_ctrl(
    bio: *mut Bio,
    cmd: c_int,
    num: c_long,
    ptr_: *mut c_void,
) -> c_long {
    match cmd {
        BIO_C_MAKE_BIO_PAIR => {
            // SAFETY: the control's contract says `ptr_` is a BIO.
            unsafe { dgram_pair_ctrl_make_bio_pair(bio, ptr_.cast()) as c_long }
        }
        BIO_C_DESTROY_BIO_PAIR => {
            // SAFETY: `bio` is live.
            unsafe { dgram_pair_ctrl_destroy_bio_pair(bio) as c_long }
        }
        BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS => {
            // SAFETY: `bio` is live.
            unsafe { dgram_pair_ctrl_get_effective_caps(bio) as c_long }
        }
        _ => {
            // SAFETY: `bio` is live.
            unsafe { dgram_mem_ctrl(bio, cmd, num, ptr_) }
        }
    }
}

/// `dgram_pair_read_actual`.
///
/// Returns the number of bytes read, or a **negated** `BIO_R_*` code. The caller
/// decides what to raise and whether to set a retry flag, which is why the
/// negated-code convention is kept rather than folded into the raise.
///
/// # Safety
/// `bio` must be a live BIO; `buf` writable for `sz` bytes or NULL; `local` and
/// `peer` writable or NULL.
unsafe fn dgram_pair_read_actual(
    bio: *mut Bio,
    buf: *mut u8,
    mut sz: usize,
    local: *mut [u8; HDR_ADDR_SIZE],
    peer: *mut [u8; HDR_ADDR_SIZE],
    is_multi: bool,
) -> isize {
    if !is_multi {
        // SAFETY: `bio` is live.
        unsafe { super::BIO_clear_flags(bio, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };
    }
    // SAFETY: `bio` is live.
    if unsafe { (*bio).init } == 0 {
        return -(BIO_R_UNINITIALIZED as isize);
    }
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    if b.is_null() {
        return -(BIO_R_TRANSFER_ERROR as isize);
    }
    // SAFETY: `b` is live.
    let readb = if unsafe { is_pair(b) } {
        // SAFETY: `b` is live and paired.
        unsafe { peer_ctx(b) }
    } else {
        b
    };
    if readb.is_null() {
        return -(BIO_R_TRANSFER_ERROR as isize);
    }
    // SAFETY: `readb` is live — either `b` itself or, when paired, its peer,
    // both of which are initialised dgram-pair contexts.
    if unsafe { (*readb).rbuf.start.is_null() } {
        return -(BIO_R_TRANSFER_ERROR as isize);
    }
    if sz > 0 && buf.is_null() {
        return -(BIO_R_INVALID_ARGUMENT as isize);
    }
    // A caller that wants the local address must have enabled it.
    // SAFETY: `b` is live.
    if !local.is_null() && !unsafe { (*b).local_addr_enable } {
        return -(BIO_R_LOCAL_ADDR_NOT_AVAILABLE as isize);
    }

    // SAFETY: `readb` is live and its ring is initialised.
    let (saved_idx, saved_count) = unsafe { ((*readb).rbuf.idx[1], (*readb).rbuf.count) };
    let mut hdr = DgramHdr {
        len: 0,
        src_addr: [0; HDR_ADDR_SIZE],
        dst_addr: [0; HDR_ADDR_SIZE],
    };
    let hdr_size = core::mem::size_of::<DgramHdr>();
    // SAFETY: `readb` is live; `hdr` is writable for its own size.
    let l = unsafe { dgram_pair_read_inner(readb, ptr::addr_of_mut!(hdr).cast::<u8>(), hdr_size) };
    if l == 0 {
        // The buffer was empty.
        if !is_multi {
            // SAFETY: `bio` is live.
            unsafe { super::BIO_set_flags(bio, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY) };
        }
        return -(BIO_R_NON_FATAL as isize);
    }
    if l != hdr_size {
        // Headers are written atomically, so a short one means a broken buffer.
        return -(BIO_R_BROKEN_PIPE as isize);
    }

    let mut trunc = 0usize;
    if sz > hdr.len {
        sz = hdr.len;
    } else if sz < hdr.len {
        trunc = hdr.len - sz;
        // SAFETY: `b` is live.
        if unsafe { (*b).no_trunc } {
            // Restore the cursor: nothing was consumed.
            // SAFETY: `readb` is live.
            unsafe {
                (*readb).rbuf.idx[1] = saved_idx;
                (*readb).rbuf.count = saved_count;
            }
            return -(BIO_R_NON_FATAL as isize);
        }
    }

    // SAFETY: `readb` is live and `buf` is writable for `sz` bytes.
    let got = unsafe { dgram_pair_read_inner(readb, buf, sz) };
    if got != sz {
        return -(BIO_R_TRANSFER_ERROR as isize);
    }
    if trunc > 0 {
        // SAFETY: `readb` is live; the destination is null because the caller
        // only wants the remainder consumed.
        let rest = unsafe { dgram_pair_read_inner(readb, ptr::null_mut(), trunc) };
        if rest != trunc {
            return -(BIO_R_TRANSFER_ERROR as isize);
        }
    }

    if !local.is_null() {
        // SAFETY: `local` is writable.
        unsafe { *local = hdr.dst_addr };
    }
    if !peer.is_null() {
        // SAFETY: `peer` is writable.
        unsafe { *peer = hdr.src_addr };
    }
    got as isize
}

/// `dgram_pair_lock_both_write`
///
/// # Safety
/// `a` and `b` must be live contexts owning their locks.
unsafe fn dgram_pair_lock_both_write(a: *mut BioDgramPairSt, b: *mut BioDgramPairSt) -> c_int {
    // SAFETY: both are live.
    let (x, y) = unsafe {
        if (*a).role {
            (a, b)
        } else {
            (b, a)
        }
    };
    // SAFETY: both are live.
    unsafe {
        if CRYPTO_THREAD_write_lock((*x).lock) == 0 {
            return 0;
        }
        if CRYPTO_THREAD_write_lock((*y).lock) == 0 {
            CRYPTO_THREAD_unlock((*x).lock);
            return 0;
        }
    }
    1
}

/// `dgram_pair_unlock_both`
///
/// # Safety
/// Both locks must be held by the caller.
unsafe fn dgram_pair_unlock_both(a: *mut BioDgramPairSt, b: *mut BioDgramPairSt) {
    // SAFETY: both are live and their locks are held.
    unsafe {
        CRYPTO_THREAD_unlock((*a).lock);
        CRYPTO_THREAD_unlock((*b).lock);
    }
}

/// `dgram_pair_read`
///
/// # Safety
/// `bio` must be a live pair BIO; `buf` writable for `sz_` bytes or NULL.
unsafe extern "C" fn dgram_pair_read(bio: *mut Bio, buf: *mut c_char, sz_: c_int) -> c_int {
    if sz_ < 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_DGRAM_PAIR_1018) };
        return -1;
    }
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is live.
    if unsafe { (*b).peer.is_null() } {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_DGRAM_PAIR_1023) };
        return -1;
    }
    // SAFETY: `b` is live and paired.
    let peerb = unsafe { peer_ctx(b) };
    // `BIO_read` takes both locks because it touches the local retry flags.
    // SAFETY: both are live.
    if unsafe { dgram_pair_lock_both_write(peerb, b) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_DGRAM_PAIR_1035) };
        return -1;
    }
    // SAFETY: `bio` is live and `buf` is writable for `sz_`.
    let l = unsafe {
        dgram_pair_read_actual(
            bio,
            buf.cast(),
            sz_ as usize,
            ptr::null_mut(),
            ptr::null_mut(),
            false,
        )
    };
    let ret = if l < 0 {
        if l != -(BIO_R_NON_FATAL as isize) {
            // SAFETY: the site is a compile-time constant and the reason is the
            // negated code the engine returned.
            unsafe { raise_site_dynamic(&BSS_DGRAM_PAIR_1042, -l as c_int) };
        }
        -1
    } else {
        l as c_int
    };
    // SAFETY: both locks are held.
    unsafe { dgram_pair_unlock_both(peerb, b) };
    ret
}

/// `dgram_mem_read`
///
/// # Safety
/// `bio` must be a live `BIO_s_dgram_mem` BIO; `buf` writable for `sz_` bytes.
unsafe extern "C" fn dgram_mem_read(bio: *mut Bio, buf: *mut c_char, sz_: c_int) -> c_int {
    if sz_ < 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_DGRAM_PAIR_1120) };
        return -1;
    }
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is live and owns its lock.
    if unsafe { CRYPTO_THREAD_write_lock((*b).lock) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_DGRAM_PAIR_1125) };
        return -1;
    }
    // SAFETY: `bio` is live and `buf` is writable for `sz_`.
    let l = unsafe {
        dgram_pair_read_actual(
            bio,
            buf.cast(),
            sz_ as usize,
            ptr::null_mut(),
            ptr::null_mut(),
            false,
        )
    };
    let ret = if l < 0 {
        if l != -(BIO_R_NON_FATAL as isize) {
            // SAFETY: the site is a compile-time constant and the reason is the
            // negated code the engine returned.
            unsafe { raise_site_dynamic(&BSS_DGRAM_PAIR_1132, -l as c_int) };
        }
        -1
    } else {
        l as c_int
    };
    // SAFETY: `b` is live and its lock is held.
    unsafe { CRYPTO_THREAD_unlock((*b).lock) };
    ret
}

/// `compute_rbuf_growth` — grow by 8/5 until the target fits.
fn compute_rbuf_growth(target: usize, current: usize) -> usize {
    /// Unlimited in practice.
    const MAX_RBUF_SIZE: usize = usize::MAX / 2;
    let mut current = current;
    while current < target {
        if current >= MAX_RBUF_SIZE {
            return 0;
        }
        // `safe_muldiv_size_t(current, 8, 5)`: `current * 8` must not overflow.
        let Some(scaled) = current.checked_mul(8) else {
            return 0;
        };
        current = scaled / 5;
        if current >= MAX_RBUF_SIZE {
            current = MAX_RBUF_SIZE;
        }
    }
    current
}

/// `dgram_pair_write_inner`
///
/// # Safety
/// `b` must be a live context whose `rbuf` is initialised; `buf` readable for
/// `sz` bytes.
unsafe fn dgram_pair_write_inner(b: *mut BioDgramPairSt, buf: *const u8, mut sz: usize) -> usize {
    let mut total = 0usize;
    while sz > 0 {
        // SAFETY: `b` is live and its ring is initialised.
        let (dst, mut dst_len) = unsafe { (*b).rbuf.head_tail(0) };
        if dst_len == 0 {
            // SAFETY: `b` is live.
            if !unsafe { (*b).grows_on_write } {
                break;
            }
            // SAFETY: `b` is live.
            let new_len = unsafe { compute_rbuf_growth((*b).req_buf_len + sz, (*b).req_buf_len) };
            if new_len == 0 {
                break;
            }
            // SAFETY: `b` is live.
            if !unsafe { (*b).rbuf.resize(new_len) } {
                break;
            }
            // SAFETY: `b` is live.
            unsafe { (*b).req_buf_len = new_len };
            continue;
        }
        if dst_len > sz {
            dst_len = sz;
        }
        // SAFETY: `dst` is valid for `dst_len` bytes and `buf` for `sz >= dst_len`.
        unsafe { ptr::copy_nonoverlapping(buf.add(total), dst, dst_len) };
        // SAFETY: `b` is live.
        unsafe { (*b).rbuf.push_pop(0, dst_len) };
        sz -= dst_len;
        total += dst_len;
    }
    total
}

/// `dgram_pair_write_actual`
///
/// # Safety
/// `bio` must be a live BIO; `buf` readable for `sz` bytes or NULL; `local` and
/// `peer` readable or NULL.
unsafe fn dgram_pair_write_actual(
    bio: *mut Bio,
    buf: *const u8,
    sz: usize,
    local: *const [u8; HDR_ADDR_SIZE],
    peer: *const [u8; HDR_ADDR_SIZE],
    is_multi: bool,
) -> isize {
    if !is_multi {
        // SAFETY: `bio` is live.
        unsafe { super::BIO_clear_flags(bio, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };
    }
    // SAFETY: `bio` is live.
    if unsafe { (*bio).init } == 0 {
        return -(BIO_R_UNINITIALIZED as isize);
    }
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    if b.is_null() {
        return -(BIO_R_TRANSFER_ERROR as isize);
    }
    // SAFETY: `b` was just checked non-null and is an initialised context.
    if unsafe { (*b).rbuf.start.is_null() } {
        return -(BIO_R_TRANSFER_ERROR as isize);
    }
    if sz > 0 && buf.is_null() {
        return -(BIO_R_INVALID_ARGUMENT as isize);
    }
    // SAFETY: `b` is live.
    if !local.is_null() && !unsafe { (*b).local_addr_enable } {
        return -(BIO_R_LOCAL_ADDR_NOT_AVAILABLE as isize);
    }
    // SAFETY: `b` is live.
    let readb = if unsafe { is_pair(b) } {
        // SAFETY: `b` is live and paired.
        unsafe { peer_ctx(b) }
    } else {
        b
    };
    if !peer.is_null() {
        // SAFETY: `readb` is the live peer/self context derived above.
        let caps = unsafe { (*readb).cap };
        if caps & BIO_DGRAM_CAP_HANDLES_DST_ADDR as u32 == 0 {
            return -(BIO_R_PEER_ADDR_NOT_AVAILABLE as isize);
        }
    }

    let mut hdr = DgramHdr {
        len: sz,
        src_addr: [0; HDR_ADDR_SIZE],
        dst_addr: [0; HDR_ADDR_SIZE],
    };
    if !peer.is_null() {
        // SAFETY: `peer` is readable for one slot.
        hdr.dst_addr = unsafe { *peer };
    }
    let effective_local = if local.is_null() {
        // SAFETY: `b` is live.
        let la = unsafe { (*b).local_addr };
        if la.is_null() {
            None
        } else {
            // SAFETY: `la` is a live address; the slot copy takes its first
            // `HDR_ADDR_SIZE` bytes.
            Some(unsafe { addr_slot(la) })
        }
    } else {
        // SAFETY: `local` is readable for one slot.
        Some(unsafe { *local })
    };
    if let Some(a) = effective_local {
        hdr.src_addr = a;
    }

    // SAFETY: `b` is live.
    let (saved_idx, saved_count) = unsafe { ((*b).rbuf.idx[0], (*b).rbuf.count) };
    let hdr_size = core::mem::size_of::<DgramHdr>();
    // SAFETY: `b` is live; `hdr` is readable for its own size.
    let hdr_ok =
        unsafe { dgram_pair_write_inner(b, ptr::addr_of!(hdr).cast::<u8>(), hdr_size) } == hdr_size;
    // SAFETY: `b` is live and `buf` is readable for `sz` bytes.
    let body_ok = unsafe { dgram_pair_write_inner(b, buf, sz) } == sz;
    if !hdr_ok || !body_ok {
        // A partial datagram is not a datagram: roll back.
        // SAFETY: `b` is live.
        unsafe {
            (*b).rbuf.idx[0] = saved_idx;
            (*b).rbuf.count = saved_count;
        }
        if !is_multi {
            // SAFETY: `bio` is live.
            unsafe { super::BIO_set_flags(bio, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY) };
        }
        return -(BIO_R_NON_FATAL as isize);
    }
    sz as isize
}

/// Read the first `HDR_ADDR_SIZE` bytes of a live [`BioAddr`].
///
/// # Safety
/// `a` must point at a live `BioAddr` of at least `HDR_ADDR_SIZE` bytes.
unsafe fn addr_slot(a: *const BioAddr) -> [u8; HDR_ADDR_SIZE] {
    let mut out = [0u8; HDR_ADDR_SIZE];
    // SAFETY: the caller guarantees `HDR_ADDR_SIZE` readable bytes.
    unsafe { ptr::copy_nonoverlapping(a.cast::<u8>(), out.as_mut_ptr(), HDR_ADDR_SIZE) };
    out
}

/// `dgram_pair_write`
///
/// # Safety
/// `bio` must be a live BIO; `buf` readable for `sz_` bytes.
unsafe extern "C" fn dgram_pair_write(bio: *mut Bio, buf: *const c_char, sz_: c_int) -> c_int {
    if sz_ < 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_DGRAM_PAIR_1283) };
        return -1;
    }
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is live and owns its lock.
    if unsafe { CRYPTO_THREAD_write_lock((*b).lock) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_DGRAM_PAIR_1288) };
        return -1;
    }
    // SAFETY: `bio` is live and `buf` is readable for `sz_`.
    let l = unsafe {
        dgram_pair_write_actual(
            bio,
            buf.cast(),
            sz_ as usize,
            ptr::null(),
            ptr::null(),
            false,
        )
    };
    let ret = if l < 0 {
        // Note: a write raises even for the non-fatal case, unlike a read.
        // SAFETY: the site is a compile-time constant and the reason is the
        // negated code the engine returned.
        unsafe { raise_site_dynamic(&BSS_DGRAM_PAIR_1294, -l as c_int) };
        -1
    } else {
        l as c_int
    };
    // SAFETY: `b` is live and its lock is held.
    unsafe { CRYPTO_THREAD_unlock((*b).lock) };
    ret
}

/// One message of a `BIO_MSG` array at index `i`.
///
/// # Safety
/// `base` must point at `num_msg` messages laid out at `stride` bytes apart.
unsafe fn msg_at(base: *mut BioMsg, i: usize, stride: usize) -> *mut BioMsg {
    // SAFETY: the caller guarantees the array spans this element.
    unsafe { base.cast::<u8>().add(i * stride).cast() }
}

/// `dgram_pair_sendmmsg`
///
/// # Safety
/// `bio` must be a live BIO; `msg` must point at `num_msg` messages `stride`
/// bytes apart; `num_processed` must be writable.
unsafe extern "C" fn dgram_pair_sendmmsg(
    bio: *mut Bio,
    msg: *mut BioMsg,
    stride: usize,
    num_msg: usize,
    _flags: u64,
    num_processed: *mut usize,
) -> c_int {
    if num_msg == 0 {
        if !num_processed.is_null() {
            // SAFETY: `num_processed` is writable per the caller's contract.
            unsafe { *num_processed = 0 };
        }
        return 1;
    }
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is live and owns its lock.
    if unsafe { CRYPTO_THREAD_write_lock((*b).lock) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_DGRAM_PAIR_1321) };
        if !num_processed.is_null() {
            // SAFETY: as above.
            unsafe { *num_processed = 0 };
        }
        return 0;
    }
    let mut ret = 0;
    let mut i = 0usize;
    while i < num_msg {
        // SAFETY: `msg` spans `num_msg` messages at this stride.
        let m = unsafe { msg_at(msg, i, stride) };
        // SAFETY: `m` is live.
        let (data, data_len, local, peer) =
            unsafe { ((*m).data, (*m).data_len, (*m).local, (*m).peer) };
        let local_slot = if local.is_null() {
            None
        } else {
            // SAFETY: the caller's message carries a live address.
            Some(unsafe { addr_slot(local.cast()) })
        };
        let peer_slot = if peer.is_null() {
            None
        } else {
            // SAFETY: as above.
            Some(unsafe { addr_slot(peer.cast()) })
        };
        let local_ptr: *const [u8; HDR_ADDR_SIZE] = match local_slot {
            Some(ref s) => s,
            None => ptr::null(),
        };
        let peer_ptr: *const [u8; HDR_ADDR_SIZE] = match peer_slot {
            Some(ref s) => s,
            None => ptr::null(),
        };
        // SAFETY: `bio` is live and the message's data is readable for its length.
        let l = unsafe {
            dgram_pair_write_actual(bio, data.cast(), data_len, local_ptr, peer_ptr, true)
        };
        if l < 0 {
            if !num_processed.is_null() {
                // SAFETY: `num_processed` is writable.
                unsafe { *num_processed = i };
            }
            if i > 0 {
                ret = 1;
            } else {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site_dynamic(&BSS_DGRAM_PAIR_1335, -l as c_int) };
            }
            // SAFETY: `b` is live and its lock is held.
            unsafe { CRYPTO_THREAD_unlock((*b).lock) };
            return ret;
        }
        // SAFETY: `m` is live.
        unsafe { (*m).flags = 0 };
        i += 1;
    }
    if !num_processed.is_null() {
        // SAFETY: `num_processed` is writable.
        unsafe { *num_processed = i };
    }
    ret = 1;
    // SAFETY: `b` is live and its lock is held.
    unsafe { CRYPTO_THREAD_unlock((*b).lock) };
    ret
}

/// `dgram_pair_recvmmsg`
///
/// # Safety
/// `bio` must be a live BIO; `msg` must point at `num_msg` messages `stride`
/// bytes apart; `num_processed` must be writable.
unsafe extern "C" fn dgram_pair_recvmmsg(
    bio: *mut Bio,
    msg: *mut BioMsg,
    stride: usize,
    num_msg: usize,
    _flags: u64,
    num_processed: *mut usize,
) -> c_int {
    if num_msg == 0 {
        if !num_processed.is_null() {
            // SAFETY: `num_processed` is writable per the caller's contract.
            unsafe { *num_processed = 0 };
        }
        return 1;
    }
    // SAFETY: `bio` is live.
    if unsafe { (*bio).init } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_DGRAM_PAIR_1070) };
        if !num_processed.is_null() {
            // SAFETY: as above.
            unsafe { *num_processed = 0 };
        }
        return 0;
    }
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is live.
    let readb = if unsafe { is_pair(b) } {
        // SAFETY: `b` is live and paired.
        unsafe { peer_ctx(b) }
    } else {
        b
    };
    // SAFETY: `readb` is live and owns its lock.
    if unsafe { CRYPTO_THREAD_write_lock((*readb).lock) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_DGRAM_PAIR_1081) };
        if !num_processed.is_null() {
            // SAFETY: as above.
            unsafe { *num_processed = 0 };
        }
        return 0;
    }
    let mut ret = 0;
    let mut i = 0usize;
    while i < num_msg {
        // SAFETY: `msg` spans `num_msg` messages at this stride.
        let m = unsafe { msg_at(msg, i, stride) };
        // SAFETY: `m` is live.
        let (data, data_len, local, peer) =
            unsafe { ((*m).data, (*m).data_len, (*m).local, (*m).peer) };
        let local_slot = if local.is_null() {
            None
        } else {
            // SAFETY: the caller's message carries a live address.
            Some(unsafe { addr_slot(local.cast()) })
        };
        let peer_slot = if peer.is_null() {
            None
        } else {
            // SAFETY: as above.
            Some(unsafe { addr_slot(peer.cast()) })
        };
        let mut local_slot = local_slot;
        let mut peer_slot = peer_slot;
        let local_ptr: *mut [u8; HDR_ADDR_SIZE] = match local_slot {
            Some(ref mut s) => s,
            None => ptr::null_mut(),
        };
        let peer_ptr: *mut [u8; HDR_ADDR_SIZE] = match peer_slot {
            Some(ref mut s) => s,
            None => ptr::null_mut(),
        };
        // SAFETY: `bio` is live and the message's buffer is writable for its length.
        let l = unsafe {
            dgram_pair_read_actual(bio, data.cast(), data_len, local_ptr, peer_ptr, true)
        };
        if l < 0 {
            if !num_processed.is_null() {
                // SAFETY: `num_processed` is writable.
                unsafe { *num_processed = i };
            }
            if i > 0 {
                ret = 1;
            } else {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site_dynamic(&BSS_DGRAM_PAIR_1095, -l as c_int) };
            }
            // SAFETY: `readb` is live and its lock is held.
            unsafe { CRYPTO_THREAD_unlock((*readb).lock) };
            return ret;
        }
        // SAFETY: `m` is live.
        unsafe {
            (*m).data_len = l as usize;
            (*m).flags = 0;
        }
        i += 1;
    }
    if !num_processed.is_null() {
        // SAFETY: `num_processed` is writable.
        unsafe { *num_processed = i };
    }
    ret = 1;
    // SAFETY: `readb` is live and its lock is held.
    unsafe { CRYPTO_THREAD_unlock((*readb).lock) };
    ret
}

/// `int BIO_new_bio_dgram_pair(BIO **pbio1, size_t writebuf1, BIO **pbio2, size_t writebuf2)`
///
/// # Safety
/// `pbio1` and `pbio2` must each be writable.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_bio_dgram_pair(
    pbio1: *mut *mut Bio,
    writebuf1: usize,
    pbio2: *mut *mut Bio,
    writebuf2: usize,
) -> c_int {
    guard_ffi(0, || {
        let mut bio1: *mut Bio = ptr::null_mut();
        let mut bio2: *mut Bio = ptr::null_mut();
        let mut ret = 0;

        'build: {
            if writebuf1 > c_long::MAX as usize || writebuf2 > c_long::MAX as usize {
                break 'build;
            }
            // SAFETY: `BIO_s_dgram_pair` returns a static method table.
            bio1 = unsafe { super::BIO_new(BIO_s_dgram_pair()) };
            if bio1.is_null() {
                break 'build;
            }
            // SAFETY: as above.
            bio2 = unsafe { super::BIO_new(BIO_s_dgram_pair()) };
            if bio2.is_null() {
                break 'build;
            }
            if writebuf1 > 0 {
                // SAFETY: `bio1` is live.
                if unsafe {
                    super::BIO_ctrl(
                        bio1,
                        BIO_C_SET_WRITE_BUF_SIZE,
                        writebuf1 as c_long,
                        ptr::null_mut(),
                    )
                } == 0
                {
                    break 'build;
                }
            }
            if writebuf2 > 0 {
                // SAFETY: `bio2` is live.
                if unsafe {
                    super::BIO_ctrl(
                        bio2,
                        BIO_C_SET_WRITE_BUF_SIZE,
                        writebuf2 as c_long,
                        ptr::null_mut(),
                    )
                } == 0
                {
                    break 'build;
                }
            }
            // SAFETY: both are live and are dgram-pair BIOs.
            if unsafe { dgram_pair_ctrl_make_bio_pair(bio1, bio2) } == 0 {
                break 'build;
            }
            ret = 1;
        }

        if ret == 0 {
            // SAFETY: each is NULL or owned here.
            unsafe {
                super::BIO_free(bio1);
                bio1 = ptr::null_mut();
                super::BIO_free(bio2);
                bio2 = ptr::null_mut();
            }
        }
        if !pbio1.is_null() {
            // SAFETY: `pbio1` is writable per the caller's contract.
            unsafe { *pbio1 = bio1 };
        }
        if !pbio2.is_null() {
            // SAFETY: `pbio2` is writable per the caller's contract.
            unsafe { *pbio2 = bio2 };
        }
        ret
    })
}
