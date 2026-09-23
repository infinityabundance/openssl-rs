//! Phase 8 — `crypto/packet.c`: the write-side packet builder (`WPACKET_*`).
//!
//! This unit has no stratum's plan row and no crate module before this one. It is transcribed
//! because the DSA landing surfaced it: `crypto/dsa/dsa_sign.c`'s `i2d_DSA_SIG` is a `WPACKET`
//! program, and `DSA_sign`/`DSA_verify` reach it, so the thirty `WPACKET_*` symbols are on the
//! path that lands the three DSA exports (`docs/DECISIONS.md` D333 named the blocker, D342 the
//! landing).
//!
//! **Transcribed whole** (D327's rule), including the QUIC half. `OPENSSL_NO_QUIC` is absent
//! from the admitted `configuration.h`, so the four `WPACKET_*quic*` functions and the static
//! `put_quic_value` are compiled in the authority and land here; their callee is
//! [`crate::quic_vlint`]. The `#if` in the source is the authority's own and this profile takes
//! the defined arm, so nothing here is `#ifdef`-ed out.
//!
//! ## What is modelled, and what is not
//!
//! `WPACKET` is an internal structure (`include/internal/packet.h`), so there is no ABI
//! obligation: the two structures below are `#[repr(C)]` and their field order is the header's
//! because every pointer computation in the body reads `curr`, `written`, `maxsize`, `subs` and
//! `endfirst` by name. The read side of `packet.h` — the `PACKET_*` family — is a set of
//! `static ossl_inline` functions rather than symbols of this unit, and is modelled where a
//! decoder needs it (`src/asn1_dsa.rs`), not here.
//!
//! Every `ossl_assert` in the source is a **live** guard on this build (`NDEBUG` is set, so it
//! is `(x) != 0`), which is why each is transcribed as the refusal it is rather than dropped.
//! Allocations go through [`CRYPTO_zalloc`]/[`CRYPTO_free`], which is what `OPENSSL_zalloc` and
//! `OPENSSL_free` expand to.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};

use crate::quic_vlint::{
    ossl_quic_vlint_encode, ossl_quic_vlint_encode_len, ossl_quic_vlint_encode_n,
    OSSL_QUIC_VLINT_4B_MIN,
};
use crate::runtime::buffer::{BUF_MEM_grow, BufMem};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// `DEFAULT_BUF_SIZE` — the floor `WPACKET_reserve_bytes` grows a buffer to.
const DEFAULT_BUF_SIZE: usize = 256;

/// `SIZE_MAX`, as `WPACKET_sub_reserve_bytes__` and `maxmaxsize` compare against it.
const SIZE_MAX: usize = usize::MAX;

/// `#define WPACKET_FLAGS_NONE 0` — `include/internal/packet.h:694`.
#[allow(dead_code)] // transcribed whole; no crate caller sets it (D342)
pub(crate) const WPACKET_FLAGS_NONE: c_uint = 0;
/// `#define WPACKET_FLAGS_NON_ZERO_LENGTH 1` — `include/internal/packet.h:697`.
pub(crate) const WPACKET_FLAGS_NON_ZERO_LENGTH: c_uint = 1;
/// `#define WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH 2` — `include/internal/packet.h:703`.
pub(crate) const WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH: c_uint = 2;
/// `#define WPACKET_FLAGS_QUIC_VLINT 4` — `include/internal/packet.h:706`.
pub(crate) const WPACKET_FLAGS_QUIC_VLINT: c_uint = 4;

/// `struct wpacket_sub` — `include/internal/packet.h:644-662`.
#[repr(C)]
pub(crate) struct WpacketSub {
    /// `WPACKET_SUB *parent`.
    parent: *mut WpacketSub,
    /// `size_t packet_len` — the offset of this sub-packet's length field.
    packet_len: usize,
    /// `size_t lenbytes` — how many length bytes it reserves, or 0.
    lenbytes: usize,
    /// `size_t pwritten` — bytes written before this sub-packet began.
    pwritten: usize,
    /// `unsigned int flags`.
    flags: c_uint,
}

/// `struct wpacket_st` — `include/internal/packet.h:665-689`.
#[repr(C)]
pub(crate) struct Wpacket {
    /// `BUF_MEM *buf`.
    buf: *mut BufMem,
    /// `unsigned char *staticbuf`.
    staticbuf: *mut c_uchar,
    /// `size_t curr` — an offset, so a grow cannot invalidate it.
    curr: usize,
    /// `size_t written`.
    written: usize,
    /// `size_t maxsize`.
    maxsize: usize,
    /// `WPACKET_SUB *subs`.
    subs: *mut WpacketSub,
    /// `unsigned int endfirst : 1`.
    endfirst: c_uint,
}

/// The authority translation unit, for the allocation-attribution record.
const FILE_PACKET: *const c_char = c"../../src/openssl-3.6.4/crypto/packet.c".as_ptr();
/// `__LINE__` is inert under `OPENSSL_NO_CRYPTO_MDEBUG`, which this profile defines.
const LINE: c_int = 0;

/// `GETBUF(p)` — `crypto/packet.c:40-44`: the static buffer if there is one, else the `BUF_MEM`'s
/// data, else NULL.
///
/// # Safety
///
/// `pkt` is live and, when `buf` is non-null, a live `BUF_MEM`.
unsafe fn getbuf(pkt: *const Wpacket) -> *mut c_uchar {
    // SAFETY: `pkt` is live per the contract.
    let p = unsafe { &*pkt };
    if !p.staticbuf.is_null() {
        return p.staticbuf;
    }
    if !p.buf.is_null() {
        // SAFETY: `buf` is a live `BUF_MEM` per the contract.
        return unsafe { (*p.buf).data.cast::<c_uchar>() };
    }
    core::ptr::null_mut()
}

/// `int WPACKET_allocate_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes)` —
/// `crypto/packet.c:19-27`.
///
/// # Safety
///
/// `pkt` is live; `allocbytes` is NULL or writable.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_allocate_bytes(
    pkt: *mut Wpacket,
    len: usize,
    allocbytes: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: `pkt` is live, `allocbytes` is NULL or writable.
    if unsafe { WPACKET_reserve_bytes(pkt, len, allocbytes) } == 0 {
        return 0;
    }
    // SAFETY: `pkt` is live.
    unsafe {
        (*pkt).written += len;
        (*pkt).curr += len;
    }
    1
}

/// `int WPACKET_sub_allocate_bytes__(WPACKET *pkt, size_t len, unsigned char **allocbytes,`
/// `size_t lenbytes)` — `crypto/packet.c:29-38`.
///
/// # Safety
///
/// `pkt` is live; `allocbytes` is NULL or writable.
#[allow(dead_code)] // transcribed whole; the DER path does not use it (D342)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_sub_allocate_bytes__(
    pkt: *mut Wpacket,
    len: usize,
    allocbytes: *mut *mut c_uchar,
    lenbytes: usize,
) -> c_int {
    // SAFETY: `pkt` is live and `allocbytes` is NULL or writable throughout.
    unsafe {
        if WPACKET_start_sub_packet_len__(pkt, lenbytes) == 0
            || WPACKET_allocate_bytes(pkt, len, allocbytes) == 0
            || WPACKET_close(pkt) == 0
        {
            return 0;
        }
    }
    1
}

/// `int WPACKET_reserve_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes)` —
/// `crypto/packet.c:46-78`.
///
/// # Safety
///
/// `pkt` is live; `allocbytes` is NULL or writable.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_reserve_bytes(
    pkt: *mut Wpacket,
    len: usize,
    allocbytes: *mut *mut c_uchar,
) -> c_int {
    /* `ossl_assert(pkt->subs != NULL && len != 0)`, a live guard under `NDEBUG`. */
    // SAFETY: `pkt` is live.
    if unsafe { (*pkt).subs.is_null() } || len == 0 {
        return 0;
    }

    // SAFETY: `pkt` is live.
    unsafe {
        if size_max_minus((*pkt).maxsize, (*pkt).written) < len {
            return 0;
        }

        if !(*pkt).buf.is_null() && size_max_minus((*(*pkt).buf).length, (*pkt).written) < len {
            let reflen = if len > (*(*pkt).buf).length {
                len
            } else {
                (*(*pkt).buf).length
            };

            let newlen = if reflen > SIZE_MAX / 2 {
                SIZE_MAX
            } else {
                let mut newlen = reflen * 2;
                if newlen < DEFAULT_BUF_SIZE {
                    newlen = DEFAULT_BUF_SIZE;
                }
                newlen
            };
            if BUF_MEM_grow((*pkt).buf, newlen) == 0 {
                return 0;
            }
        }
        if !allocbytes.is_null() {
            *allocbytes = WPACKET_get_curr(pkt);
            if (*pkt).endfirst != 0 && !(*allocbytes).is_null() {
                *allocbytes = (*allocbytes).sub(len);
            }
        }
    }

    1
}

/// `pkt->maxsize - pkt->written` as the unsigned `size_t` subtraction the authority performs.
fn size_max_minus(a: usize, b: usize) -> usize {
    a.wrapping_sub(b)
}

/// `int WPACKET_sub_reserve_bytes__(WPACKET *pkt, size_t len, unsigned char **allocbytes,`
/// `size_t lenbytes)` — `crypto/packet.c:80-93`.
///
/// # Safety
///
/// `pkt` is live; `allocbytes` points at a live slot.
#[allow(dead_code)] // transcribed whole; the DER path does not use it (D342)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_sub_reserve_bytes__(
    pkt: *mut Wpacket,
    len: usize,
    allocbytes: *mut *mut c_uchar,
    lenbytes: usize,
) -> c_int {
    // SAFETY: `pkt` is live and `allocbytes` is live per the contract.
    unsafe {
        if (*pkt).endfirst != 0 && lenbytes > 0 {
            return 0;
        }

        if WPACKET_reserve_bytes(pkt, lenbytes + len, allocbytes) == 0 {
            return 0;
        }

        if !(*allocbytes).is_null() {
            *allocbytes = (*allocbytes).add(lenbytes);
        }
    }

    1
}

/// `static size_t maxmaxsize(size_t lenbytes)` — `crypto/packet.c:95-101`.
fn maxmaxsize(lenbytes: usize) -> usize {
    if lenbytes >= core::mem::size_of::<usize>() || lenbytes == 0 {
        return SIZE_MAX;
    }

    ((1usize << (lenbytes * 8)) - 1) + lenbytes
}

/// `static int wpacket_intern_init_len(WPACKET *pkt, size_t lenbytes)` —
/// `crypto/packet.c:103-127`.
///
/// # Safety
///
/// `pkt` is live with its `buf`/`staticbuf`/`maxsize`/`endfirst` already set.
unsafe fn wpacket_intern_init_len(pkt: *mut Wpacket, lenbytes: usize) -> c_int {
    // SAFETY: `pkt` is live per the contract.
    unsafe {
        (*pkt).curr = 0;
        (*pkt).written = 0;

        (*pkt).subs = CRYPTO_zalloc(core::mem::size_of::<WpacketSub>(), FILE_PACKET, LINE)
            .cast::<WpacketSub>();
        if (*pkt).subs.is_null() {
            return 0;
        }

        if lenbytes == 0 {
            return 1;
        }

        (*(*pkt).subs).pwritten = lenbytes;
        (*(*pkt).subs).lenbytes = lenbytes;

        let mut lenchars: *mut c_uchar = core::ptr::null_mut();
        if WPACKET_allocate_bytes(pkt, lenbytes, &mut lenchars) == 0 {
            CRYPTO_free((*pkt).subs.cast(), FILE_PACKET, LINE);
            (*pkt).subs = core::ptr::null_mut();
            return 0;
        }
        (*(*pkt).subs).packet_len = 0;
    }

    1
}

/// `int WPACKET_init_static_len(WPACKET *pkt, unsigned char *buf, size_t len, size_t lenbytes)` —
/// `crypto/packet.c:129-144`.
///
/// # Safety
///
/// `pkt` is live; `buf` is writable for `len` bytes and outlives the packet.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_init_static_len(
    pkt: *mut Wpacket,
    buf: *mut c_uchar,
    len: usize,
    lenbytes: usize,
) -> c_int {
    let max = maxmaxsize(lenbytes);

    /* `ossl_assert(buf != NULL && len > 0)`, a live guard under `NDEBUG`. */
    if buf.is_null() || len == 0 {
        return 0;
    }

    // SAFETY: `pkt` is live; `buf` outlives the packet per the contract.
    unsafe {
        (*pkt).staticbuf = buf;
        (*pkt).buf = core::ptr::null_mut();
        (*pkt).maxsize = if max < len { max } else { len };
        (*pkt).endfirst = 0;

        wpacket_intern_init_len(pkt, lenbytes)
    }
}

/// `int WPACKET_init_der(WPACKET *pkt, unsigned char *buf, size_t len)` —
/// `crypto/packet.c:146-158`.
///
/// # Safety
///
/// `pkt` is live; `buf` is writable for `len` bytes and outlives the packet.
#[allow(dead_code)] // transcribed whole; the DER path does not use it (D342)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_init_der(
    pkt: *mut Wpacket,
    buf: *mut c_uchar,
    len: usize,
) -> c_int {
    /* `ossl_assert(buf != NULL && len > 0)`, a live guard under `NDEBUG`. */
    if buf.is_null() || len == 0 {
        return 0;
    }

    // SAFETY: `pkt` is live; `buf` outlives the packet per the contract.
    unsafe {
        (*pkt).staticbuf = buf;
        (*pkt).buf = core::ptr::null_mut();
        (*pkt).maxsize = len;
        (*pkt).endfirst = 1;

        wpacket_intern_init_len(pkt, 0)
    }
}

/// `int WPACKET_init_len(WPACKET *pkt, BUF_MEM *buf, size_t lenbytes)` —
/// `crypto/packet.c:160-172`.
///
/// # Safety
///
/// `pkt` is live; `buf` is a live `BUF_MEM` that outlives the packet.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_init_len(
    pkt: *mut Wpacket,
    buf: *mut BufMem,
    lenbytes: usize,
) -> c_int {
    /* `ossl_assert(buf != NULL)`, a live guard under `NDEBUG`. */
    if buf.is_null() {
        return 0;
    }

    // SAFETY: `pkt` is live; `buf` is a live `BUF_MEM` per the contract.
    unsafe {
        (*pkt).staticbuf = core::ptr::null_mut();
        (*pkt).buf = buf;
        (*pkt).maxsize = maxmaxsize(lenbytes);
        (*pkt).endfirst = 0;

        wpacket_intern_init_len(pkt, lenbytes)
    }
}

/// `int WPACKET_init(WPACKET *pkt, BUF_MEM *buf)` — `crypto/packet.c:174-177`.
///
/// # Safety
///
/// As [`WPACKET_init_len`] with `lenbytes == 0`.
#[allow(dead_code)] // transcribed whole; the DER path does not use it (D342)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_init(pkt: *mut Wpacket, buf: *mut BufMem) -> c_int {
    // SAFETY: `pkt` and `buf` are live per the contract.
    unsafe { WPACKET_init_len(pkt, buf, 0) }
}

/// `int WPACKET_init_null(WPACKET *pkt, size_t lenbytes)` — `crypto/packet.c:179-187`.
///
/// A packet with no buffer at all: it counts bytes and writes nothing, which is how a caller
/// sizes an encoding before allocating for it.
///
/// # Safety
///
/// `pkt` is live.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_init_null(pkt: *mut Wpacket, lenbytes: usize) -> c_int {
    // SAFETY: `pkt` is live per the contract.
    unsafe {
        (*pkt).staticbuf = core::ptr::null_mut();
        (*pkt).buf = core::ptr::null_mut();
        (*pkt).maxsize = maxmaxsize(lenbytes);
        (*pkt).endfirst = 0;

        wpacket_intern_init_len(pkt, 0)
    }
}

/// `int WPACKET_init_null_der(WPACKET *pkt)` — `crypto/packet.c:189-197`.
///
/// # Safety
///
/// `pkt` is live.
#[allow(dead_code)] // transcribed whole; the DER path does not use it (D342)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_init_null_der(pkt: *mut Wpacket) -> c_int {
    // SAFETY: `pkt` is live per the contract.
    unsafe {
        (*pkt).staticbuf = core::ptr::null_mut();
        (*pkt).buf = core::ptr::null_mut();
        (*pkt).maxsize = SIZE_MAX;
        (*pkt).endfirst = 1;

        wpacket_intern_init_len(pkt, 0)
    }
}

/// `int WPACKET_set_flags(WPACKET *pkt, unsigned int flags)` — `crypto/packet.c:199-208`.
///
/// # Safety
///
/// `pkt` is live with a sub-packet.
#[allow(dead_code)] // transcribed whole; the DER path does not use it (D342)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_set_flags(pkt: *mut Wpacket, flags: c_uint) -> c_int {
    /* `ossl_assert(pkt->subs != NULL)`, a live guard under `NDEBUG`. */
    // SAFETY: `pkt` is live.
    if unsafe { (*pkt).subs.is_null() } {
        return 0;
    }

    // SAFETY: `pkt` is live with a sub-packet.
    unsafe {
        (*(*pkt).subs).flags = flags;
    }

    1
}

/// `static int put_value(unsigned char *data, uint64_t value, size_t len)` —
/// `crypto/packet.c:211-227`.
///
/// A NULL `data` is a success with nothing written: that is the sizing pass.
///
/// The value is written **back to front within its `len` bytes**: the authority advances the
/// cursor to `data + len - 1` before the loop and walks down, so the first byte of the span is
/// the most significant. A cursor that started at `data` would shift every multi-byte field by
/// `len - 1` and overwrite the bytes before it.
fn put_value(mut data: *mut c_uchar, mut value: u64, mut len: usize) -> c_int {
    if data.is_null() {
        return 1;
    }

    if len > 0 {
        // SAFETY: `data` is writable for `len` bytes per the caller's contract, and `len > 0`, so
        // `data + len - 1` is the last of them.
        data = unsafe { data.add(len - 1) };
    }

    while len > 0 {
        // SAFETY: as above; the cursor walks down within the same `len`-byte span.
        unsafe {
            *data = (value & 0xff) as c_uchar;
            data = data.sub(1);
        }
        value >>= 8;
        len -= 1;
    }

    /* Whether the value fit in the assigned number of bytes. */
    if value > 0 {
        return 0;
    }

    1
}

/// `static int put_quic_value(unsigned char *data, size_t value, size_t len)` —
/// `crypto/packet.c:230-241`.
fn put_quic_value(data: *mut c_uchar, value: usize, len: usize) -> c_int {
    if data.is_null() {
        return 1;
    }

    /* Value too large for field. */
    if ossl_quic_vlint_encode_len(value as u64) > len {
        return 0;
    }

    // SAFETY: the caller's contract gives `data` `len` writable bytes and the length test above
    // established the value fits the QUIC width, which is `encode_n`'s precondition.
    unsafe { ossl_quic_vlint_encode_n(data, value as u64, len as c_int) };
    1
}

/// `static int wpacket_intern_close(WPACKET *pkt, WPACKET_SUB *sub, int doclose)` —
/// `crypto/packet.c:250-318`.
///
/// # Safety
///
/// `pkt` is live and `sub` is one of its live sub-packets.
unsafe fn wpacket_intern_close(pkt: *mut Wpacket, sub: *mut WpacketSub, doclose: c_int) -> c_int {
    // SAFETY: `pkt` and `sub` are live per the contract.
    let packlen = unsafe { (*pkt).written - (*sub).pwritten };

    // SAFETY: `sub` is live.
    if packlen == 0 && (unsafe { (*sub).flags } & WPACKET_FLAGS_NON_ZERO_LENGTH) != 0 {
        return 0;
    }

    // SAFETY: `sub` is live.
    if packlen == 0 && (unsafe { (*sub).flags } & WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH) != 0 {
        /* We can't handle this case. Return an error. */
        if doclose == 0 {
            return 0;
        }

        // SAFETY: `pkt` and `sub` are live.
        unsafe {
            if (*pkt).curr - (*sub).lenbytes == (*sub).packet_len {
                (*pkt).written -= (*sub).lenbytes;
                (*pkt).curr -= (*sub).lenbytes;
            }

            /* Don't write out the packet length. */
            (*sub).packet_len = 0;
            (*sub).lenbytes = 0;
        }
    }

    /* Write out the WPACKET length if needed. */
    // SAFETY: `pkt` and `sub` are live.
    if unsafe { (*sub).lenbytes } > 0 {
        // SAFETY: `pkt` is live.
        let buf = unsafe { getbuf(pkt) };

        if !buf.is_null() {
            // SAFETY: `pkt` and `sub` are live; the buffer is writable at the recorded offset.
            unsafe {
                if ((*sub).flags & WPACKET_FLAGS_QUIC_VLINT) == 0 {
                    if put_value(buf.add((*sub).packet_len), packlen as u64, (*sub).lenbytes) == 0 {
                        return 0;
                    }
                } else if put_quic_value(buf.add((*sub).packet_len), packlen, (*sub).lenbytes) == 0
                {
                    return 0;
                }
            }
        }
    } else {
        // SAFETY: `pkt` and `sub` are live.
        let (endfirst, has_parent, sub_flags) =
            unsafe { ((*pkt).endfirst, !(*sub).parent.is_null(), (*sub).flags) };
        if endfirst != 0
            && has_parent
            && (packlen != 0 || (sub_flags & WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH) == 0)
        {
            let mut tmplen = packlen;
            let mut numlenbytes: usize = 1;

            while {
                tmplen >>= 8;
                tmplen > 0
            } {
                numlenbytes += 1;
            }
            // SAFETY: `pkt` is live.
            if unsafe { WPACKET_put_bytes__(pkt, packlen as u64, numlenbytes) } == 0 {
                return 0;
            }
            if packlen > 0x7f {
                numlenbytes |= 0x80;
                // SAFETY: `pkt` is live.
                if unsafe { WPACKET_put_bytes_u8(pkt, numlenbytes as u8) } == 0 {
                    return 0;
                }
            }
        }
    }

    if doclose != 0 {
        // SAFETY: `pkt` and `sub` are live; `sub->parent` is live or NULL.
        unsafe {
            (*pkt).subs = (*sub).parent;
            CRYPTO_free(sub.cast(), FILE_PACKET, LINE);
        }
    }

    1
}

/// `int WPACKET_fill_lengths(WPACKET *pkt)` — `crypto/packet.c:320-333`.
///
/// # Safety
///
/// `pkt` is live with a sub-packet.
#[allow(dead_code)] // transcribed whole; the DER path does not use it (D342)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_fill_lengths(pkt: *mut Wpacket) -> c_int {
    /* `ossl_assert(pkt->subs != NULL)`, a live guard under `NDEBUG`. */
    // SAFETY: `pkt` is live.
    if unsafe { (*pkt).subs.is_null() } {
        return 0;
    }

    // SAFETY: `pkt` is live; each `sub` is one of its live sub-packets, walked through `parent`.
    unsafe {
        let mut sub = (*pkt).subs;
        while !sub.is_null() {
            if wpacket_intern_close(pkt, sub, 0) == 0 {
                return 0;
            }
            sub = (*sub).parent;
        }
    }

    1
}

/// `int WPACKET_close(WPACKET *pkt)` — `crypto/packet.c:335-345`.
///
/// # Safety
///
/// `pkt` is live.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_close(pkt: *mut Wpacket) -> c_int {
    /* No assert: the authority negative-tests this entry point. */
    // SAFETY: `pkt` is live.
    unsafe {
        if (*pkt).subs.is_null() || (*(*pkt).subs).parent.is_null() {
            return 0;
        }

        wpacket_intern_close(pkt, (*pkt).subs, 1)
    }
}

/// `int WPACKET_finish(WPACKET *pkt)` — `crypto/packet.c:347-365`.
///
/// # Safety
///
/// `pkt` is live.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_finish(pkt: *mut Wpacket) -> c_int {
    /* No assert: the authority negative-tests this entry point. */
    // SAFETY: `pkt` is live.
    unsafe {
        if (*pkt).subs.is_null() || !(*(*pkt).subs).parent.is_null() {
            return 0;
        }

        let ret = wpacket_intern_close(pkt, (*pkt).subs, 1);
        if ret != 0 {
            CRYPTO_free((*pkt).subs.cast(), FILE_PACKET, LINE);
            (*pkt).subs = core::ptr::null_mut();
        }

        ret
    }
}

/// `int WPACKET_start_sub_packet_len__(WPACKET *pkt, size_t lenbytes)` —
/// `crypto/packet.c:367-399`.
///
/// # Safety
///
/// `pkt` is live with a sub-packet.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_start_sub_packet_len__(
    pkt: *mut Wpacket,
    lenbytes: usize,
) -> c_int {
    /* `ossl_assert(pkt->subs != NULL)`, a live guard under `NDEBUG`. */
    // SAFETY: `pkt` is live.
    if unsafe { (*pkt).subs.is_null() } {
        return 0;
    }

    /* We don't support lenbytes greater than 0 when doing endfirst writing. */
    // SAFETY: `pkt` is live.
    if lenbytes > 0 && unsafe { (*pkt).endfirst } != 0 {
        return 0;
    }

    // SAFETY: `pkt` is live.
    let sub =
        CRYPTO_zalloc(core::mem::size_of::<WpacketSub>(), FILE_PACKET, LINE).cast::<WpacketSub>();
    if sub.is_null() {
        return 0;
    }

    // SAFETY: `pkt` and `sub` are live.
    unsafe {
        (*sub).parent = (*pkt).subs;
        (*pkt).subs = sub;
        (*sub).pwritten = (*pkt).written + lenbytes;
        (*sub).lenbytes = lenbytes;
    }

    if lenbytes == 0 {
        // SAFETY: `sub` is live.
        unsafe {
            (*sub).packet_len = 0;
        }
        return 1;
    }

    // SAFETY: `pkt` and `sub` are live.
    unsafe {
        (*sub).packet_len = (*pkt).written;

        let mut lenchars: *mut c_uchar = core::ptr::null_mut();
        if WPACKET_allocate_bytes(pkt, lenbytes, &mut lenchars) == 0 {
            return 0;
        }
    }

    1
}

/// `int WPACKET_start_sub_packet(WPACKET *pkt)` — `crypto/packet.c:401-404`.
///
/// # Safety
///
/// `pkt` is live.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_start_sub_packet(pkt: *mut Wpacket) -> c_int {
    // SAFETY: `pkt` is live per the contract.
    unsafe { WPACKET_start_sub_packet_len__(pkt, 0) }
}

/// `int WPACKET_put_bytes__(WPACKET *pkt, uint64_t val, size_t size)` —
/// `crypto/packet.c:406-417`.
///
/// # Safety
///
/// `pkt` is live.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_put_bytes__(
    pkt: *mut Wpacket,
    val: u64,
    size: usize,
) -> c_int {
    let mut data: *mut c_uchar = core::ptr::null_mut();

    /* `ossl_assert(size <= sizeof(uint64_t))`, a live guard under `NDEBUG`. */
    if size > core::mem::size_of::<u64>()
        // SAFETY: `pkt` is live and `data` is a live local.
        || unsafe { WPACKET_allocate_bytes(pkt, size, &mut data) } == 0
        || put_value(data, val, size) == 0
    {
        return 0;
    }

    1
}

/// `WPACKET_put_bytes_u8(pkt, val)` — `include/internal/packet.h:888-890`.
///
/// # Safety
///
/// `pkt` is live.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_put_bytes_u8(pkt: *mut Wpacket, val: u8) -> c_int {
    // SAFETY: `pkt` is live per the contract.
    unsafe { WPACKET_put_bytes__(pkt, val as u64, 1) }
}

/// `WPACKET_put_bytes_u16(pkt, val)` — `include/internal/packet.h:890-892`.
///
/// # Safety
///
/// `pkt` is live.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_put_bytes_u16(pkt: *mut Wpacket, val: u16) -> c_int {
    // SAFETY: `pkt` is live per the contract.
    unsafe { WPACKET_put_bytes__(pkt, val as u64, 2) }
}

/// `int WPACKET_set_max_size(WPACKET *pkt, size_t maxsize)` — `crypto/packet.c:419-442`.
///
/// # Safety
///
/// `pkt` is live with a sub-packet.
#[allow(dead_code)] // transcribed whole; the DER path does not use it (D342)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_set_max_size(pkt: *mut Wpacket, maxsize: usize) -> c_int {
    /* `ossl_assert(pkt->subs != NULL)`, a live guard under `NDEBUG`. */
    // SAFETY: `pkt` is live.
    unsafe {
        if (*pkt).subs.is_null() {
            return 0;
        }

        /* Find the WPACKET_SUB for the top level. */
        let mut sub = (*pkt).subs;
        while !(*sub).parent.is_null() {
            sub = (*sub).parent;
        }

        let mut lenbytes = (*sub).lenbytes;
        if lenbytes == 0 {
            lenbytes = core::mem::size_of_val(&(*pkt).maxsize);
        }

        if maxmaxsize(lenbytes) < maxsize || maxsize < (*pkt).written {
            return 0;
        }

        (*pkt).maxsize = maxsize;
    }

    1
}

/// `int WPACKET_memset(WPACKET *pkt, int ch, size_t len)` — `crypto/packet.c:444-458`.
///
/// # Safety
///
/// `pkt` is live.
#[allow(dead_code)] // transcribed whole; the DER path does not use it (D342)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_memset(pkt: *mut Wpacket, ch: c_int, len: usize) -> c_int {
    let mut dest: *mut c_uchar = core::ptr::null_mut();

    if len == 0 {
        return 1;
    }

    // SAFETY: `pkt` is live and `dest` is a live local.
    if unsafe { WPACKET_allocate_bytes(pkt, len, &mut dest) } == 0 {
        return 0;
    }

    if !dest.is_null() {
        // SAFETY: `dest` is writable for `len` bytes.
        unsafe { core::ptr::write_bytes(dest, (ch & 0xff) as u8, len) };
    }

    1
}

/// `int WPACKET_memcpy(WPACKET *pkt, const void *src, size_t len)` —
/// `crypto/packet.c:460-474`.
///
/// # Safety
///
/// `pkt` is live; `src` is readable for `len` bytes.
#[allow(dead_code)] // transcribed whole; the DER path does not use it (D342)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_memcpy(
    pkt: *mut Wpacket,
    src: *const c_void,
    len: usize,
) -> c_int {
    let mut dest: *mut c_uchar = core::ptr::null_mut();

    if len == 0 {
        return 1;
    }

    // SAFETY: `pkt` is live and `dest` is a live local.
    if unsafe { WPACKET_allocate_bytes(pkt, len, &mut dest) } == 0 {
        return 0;
    }

    if !dest.is_null() {
        // SAFETY: `dest` is writable and `src` is readable, each for `len` bytes, and the two
        // allocations do not overlap per the callers' contract.
        unsafe { core::ptr::copy_nonoverlapping(src.cast::<c_uchar>(), dest, len) };
    }

    1
}

/// `int WPACKET_sub_memcpy__(WPACKET *pkt, const void *src, size_t len, size_t lenbytes)` —
/// `crypto/packet.c:476-485`.
///
/// # Safety
///
/// `pkt` is live; `src` is readable for `len` bytes.
#[allow(dead_code)] // transcribed whole; the DER path does not use it (D342)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_sub_memcpy__(
    pkt: *mut Wpacket,
    src: *const c_void,
    len: usize,
    lenbytes: usize,
) -> c_int {
    // SAFETY: `pkt` is live and `src` is readable for `len` bytes throughout.
    unsafe {
        if WPACKET_start_sub_packet_len__(pkt, lenbytes) == 0
            || WPACKET_memcpy(pkt, src, len) == 0
            || WPACKET_close(pkt) == 0
        {
            return 0;
        }
    }

    1
}

/// `int WPACKET_get_total_written(WPACKET *pkt, size_t *written)` —
/// `crypto/packet.c:487-496`.
///
/// # Safety
///
/// `pkt` is live; `written` is NULL or writable.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_get_total_written(
    pkt: *mut Wpacket,
    written: *mut usize,
) -> c_int {
    /* `ossl_assert(written != NULL)`, a live guard under `NDEBUG`. */
    if written.is_null() {
        return 0;
    }

    // SAFETY: `pkt` is live and `written` is writable per the contract.
    unsafe {
        *written = (*pkt).written;
    }

    1
}

/// `int WPACKET_get_length(WPACKET *pkt, size_t *len)` — `crypto/packet.c:498-507`.
///
/// # Safety
///
/// `pkt` is live with a sub-packet; `len` is NULL or writable.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_get_length(pkt: *mut Wpacket, len: *mut usize) -> c_int {
    /* `ossl_assert(pkt->subs != NULL && len != NULL)`, a live guard under `NDEBUG`. */
    // SAFETY: `pkt` is live.
    unsafe {
        if (*pkt).subs.is_null() || len.is_null() {
            return 0;
        }

        *len = (*pkt).written - (*(*pkt).subs).pwritten;
    }

    1
}

/// `unsigned char *WPACKET_get_curr(WPACKET *pkt)` — `crypto/packet.c:509-520`.
///
/// # Safety
///
/// `pkt` is live.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_get_curr(pkt: *mut Wpacket) -> *mut c_uchar {
    // SAFETY: `pkt` is live per the contract.
    let buf = unsafe { getbuf(pkt) };

    if buf.is_null() {
        return core::ptr::null_mut();
    }

    // SAFETY: `pkt` is live and `buf` is its writable buffer.
    unsafe {
        if (*pkt).endfirst != 0 {
            return buf.add((*pkt).maxsize - (*pkt).curr);
        }

        buf.add((*pkt).curr)
    }
}

/// `int WPACKET_is_null_buf(WPACKET *pkt)` — `crypto/packet.c:522-525`.
///
/// # Safety
///
/// `pkt` is live.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_is_null_buf(pkt: *mut Wpacket) -> c_int {
    // SAFETY: `pkt` is live per the contract.
    unsafe { ((*pkt).buf.is_null() && (*pkt).staticbuf.is_null()) as c_int }
}

/// `void WPACKET_cleanup(WPACKET *pkt)` — `crypto/packet.c:527-536`.
///
/// # Safety
///
/// `pkt` is live.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_cleanup(pkt: *mut Wpacket) {
    // SAFETY: `pkt` is live; each `sub` is one of its live sub-packets, walked through `parent`.
    unsafe {
        let mut sub = (*pkt).subs;
        while !sub.is_null() {
            let parent = (*sub).parent;
            CRYPTO_free(sub.cast(), FILE_PACKET, LINE);
            sub = parent;
        }
        (*pkt).subs = core::ptr::null_mut();
    }
}

/// `int WPACKET_start_quic_sub_packet_bound(WPACKET *pkt, size_t max_len)` —
/// `crypto/packet.c:540-552`.
///
/// # Safety
///
/// `pkt` is live with a sub-packet.
#[allow(dead_code)] // transcribed whole; the DER path does not use it (D342)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_start_quic_sub_packet_bound(
    pkt: *mut Wpacket,
    max_len: usize,
) -> c_int {
    let enclen = ossl_quic_vlint_encode_len(max_len as u64);

    if enclen == 0 {
        return 0;
    }

    // SAFETY: `pkt` is live per the contract.
    unsafe {
        if WPACKET_start_sub_packet_len__(pkt, enclen) == 0 {
            return 0;
        }

        (*(*pkt).subs).flags |= WPACKET_FLAGS_QUIC_VLINT;
    }
    1
}

/// `int WPACKET_start_quic_sub_packet(WPACKET *pkt)` — `crypto/packet.c:554-561`.
///
/// # Safety
///
/// `pkt` is live.
#[allow(dead_code)] // transcribed whole; the DER path does not use it (D342)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_start_quic_sub_packet(pkt: *mut Wpacket) -> c_int {
    /* Assume no (sub)packet will exceed 4GiB, thus the 8-byte encoding need not be used. */
    // SAFETY: `pkt` is live per the contract.
    unsafe { WPACKET_start_quic_sub_packet_bound(pkt, OSSL_QUIC_VLINT_4B_MIN as usize) }
}

/// `int WPACKET_quic_sub_allocate_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes)` —
/// `crypto/packet.c:563-571`.
///
/// # Safety
///
/// `pkt` is live; `allocbytes` is NULL or writable.
#[allow(dead_code)] // transcribed whole; the DER path does not use it (D342)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_quic_sub_allocate_bytes(
    pkt: *mut Wpacket,
    len: usize,
    allocbytes: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: `pkt` is live and `allocbytes` is NULL or writable throughout.
    unsafe {
        if WPACKET_start_quic_sub_packet_bound(pkt, len) == 0
            || WPACKET_allocate_bytes(pkt, len, allocbytes) == 0
            || WPACKET_close(pkt) == 0
        {
            return 0;
        }
    }

    1
}

/// `int WPACKET_quic_write_vlint(WPACKET *pkt, uint64_t v)` — `crypto/packet.c:576-589`.
///
/// # Safety
///
/// `pkt` is live.
#[allow(dead_code)] // transcribed whole; the DER path does not use it (D342)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe extern "C" fn WPACKET_quic_write_vlint(pkt: *mut Wpacket, v: u64) -> c_int {
    let mut b: *mut c_uchar = core::ptr::null_mut();
    let enclen = ossl_quic_vlint_encode_len(v);

    if enclen == 0 {
        return 0;
    }

    // SAFETY: `pkt` is live and `b` is a live local.
    unsafe {
        if WPACKET_allocate_bytes(pkt, enclen, &mut b) == 0 {
            return 0;
        }

        if !b.is_null() {
            ossl_quic_vlint_encode(b, v);
        }
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The read side — `include/internal/packet.h`'s `PACKET_*` family
// ---------------------------------------------------------------------------------------------
//
// `packet.h`'s read half is a set of `static ossl_inline` functions rather than symbols of any
// translation unit. `src/asn1_dsa.rs` models the subset a DER decoder calls; the four SLH-DSA
// readers (`slh_wots.c`, `slh_xmss.c`, `slh_fors.c`, `slh_hypertree.c`, `slh_dsa.c`) call a
// second subset — `PACKET_buf_init`, `PACKET_get_bytes` and `PACKET_remaining` — which is
// modelled here because `packet.h` is this module's header. The two models are the same two
// fields and the same `PACKET_get_bytes` transition; the duplication is a later unification.

/// `PACKET` — `include/internal/packet.h:22-27`, a borrowed read cursor.
#[derive(Clone, Copy)]
pub(crate) struct Packet {
    /// `const unsigned char *curr`.
    curr: *const c_uchar,
    /// `size_t remaining`.
    remaining: usize,
}

impl Packet {
    /// `PACKET_buf_init`: a view of `len` bytes at `buf`, refusing a length above `SIZE_MAX / 2`.
    ///
    /// # Safety
    /// `buf` is readable for `len` bytes.
    #[allow(dead_code)] // the read half of the header; used by the SLH-DSA readers
    pub(crate) unsafe fn buf_init(buf: *const c_uchar, len: usize) -> Option<Packet> {
        if len > usize::MAX / 2 {
            return None;
        }
        Some(Packet {
            curr: buf,
            remaining: len,
        })
    }

    /// `PACKET_peek_bytes` + `PACKET_get_bytes`: a borrowed span, advancing.
    ///
    /// # Safety
    /// `self.curr` is readable for `self.remaining` bytes.
    #[allow(dead_code)] // the read half of the header; used by the SLH-DSA readers
    pub(crate) unsafe fn get_bytes(&mut self, len: usize) -> Option<*const c_uchar> {
        if self.remaining < len {
            return None;
        }
        let data = self.curr;
        // SAFETY: `len <= remaining`, so the advance stays inside the buffer.
        self.curr = unsafe { self.curr.add(len) };
        self.remaining -= len;
        Some(data)
    }

    /// `PACKET_remaining`: the bytes left after the cursor.
    #[allow(dead_code)] // the read half of the header; used by the SLH-DSA readers
    pub(crate) fn remaining(&self) -> usize {
        self.remaining
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::buffer::{BUF_MEM_free, BUF_MEM_new};

    #[test]
    fn a_buf_mem_backed_packet_round_trips_its_bytes() {
        // SAFETY: every pointer is a live local or an object this test owns.
        unsafe {
            let buf = BUF_MEM_new();
            assert!(!buf.is_null());
            let mut pkt = core::mem::zeroed::<Wpacket>();
            assert_eq!(WPACKET_init_len(&mut pkt, buf, 0), 1);

            assert_eq!(WPACKET_put_bytes_u8(&mut pkt, 0x30), 1);
            assert_eq!(WPACKET_start_sub_packet(&mut pkt), 1);
            assert_eq!(WPACKET_put_bytes_u16(&mut pkt, 0x0203), 1);
            assert_eq!(WPACKET_close(&mut pkt), 1);
            assert_eq!(WPACKET_put_bytes_u8(&mut pkt, 0xff), 1);

            let mut written = 0usize;
            assert_eq!(WPACKET_get_total_written(&mut pkt, &mut written), 1);
            assert_eq!(written, 4);
            assert_eq!(WPACKET_finish(&mut pkt), 1);

            // SAFETY: `buf` is live and owns the four bytes just written.
            let data = std::slice::from_raw_parts((*buf).data.cast::<u8>(), 4);
            assert_eq!(data, &[0x30, 0x02, 0x03, 0xff]);
            BUF_MEM_free(buf);
        }
    }

    #[test]
    fn a_null_packet_counts_and_writes_nothing() {
        // SAFETY: `pkt` is a live local.
        unsafe {
            let mut pkt = core::mem::zeroed::<Wpacket>();
            assert_eq!(WPACKET_init_null(&mut pkt, 0), 1);
            assert_eq!(WPACKET_is_null_buf(&mut pkt), 1);
            assert_eq!(WPACKET_put_bytes_u16(&mut pkt, 0x1234), 1);
            let mut written = 0usize;
            assert_eq!(WPACKET_get_total_written(&mut pkt, &mut written), 1);
            assert_eq!(written, 2);
            assert!(WPACKET_get_curr(&mut pkt).is_null());
            assert_eq!(WPACKET_finish(&mut pkt), 1);
        }
    }
}
