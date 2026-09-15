//! Phase 5 — `a_d2i_fp.c`: decode an item from a `BIO`, a `FILE`, or a memory buffer
//! filled from either.
//!
//! `asn1_d2i_read_bio` is the substance. It reads exactly one top-level DER object out of
//! a stream that may hold several concatenated ones, and its whole job is to decide how
//! many bytes that object occupies **before** it has them — which is what makes a caller
//! able to loop over a file of concatenated values.
//!
//! ## Why it reads headers itself rather than asking `ASN1_get_object`
//!
//! `ASN1_get_object` needs the whole header, and the stream may have delivered only part
//! of it. So the loop peeks at the bytes it has, works out how long the header *would* be
//! — a multi-byte tag and a multi-byte length both add bytes — and asks for exactly that
//! many more. Only once the header is complete does it call `ASN1_get_object` to parse it.
//!
//! `ASN1_get_object` failing with `ASN1_R_TOO_LONG` is therefore **not** fatal here: it
//! means the buffer has fewer bytes than the declared length needs. That specific reason
//! is popped off the queue (the mark is moved) and the loop reads more, which is why the
//! queue does not accumulate errors from a stream that is simply arriving in pieces.
//!
//! ## Clean EOF versus truncation
//!
//! This is the distinction the authority's own comment calls out and the reason the
//! function exists in its present shape: an EOF at a top-level object boundary
//! (`i == 0`, nothing buffered, not inside an indefinite-length value) is the **normal
//! end of input** and produces no error at all. A read failure, an EOF with bytes already
//! buffered, and an EOF while an end-of-contents marker is still owed are all
//! `ASN1_R_NOT_ENOUGH_DATA`. Callers that loop over concatenated values — the `d2i_*_bio`
//! consumers in CPython's `ssl` module are named in the comment — depend on the quiet
//! case, so a spurious error there would be observable.
//!
//! ## The error mark
//!
//! `ERR_set_mark` is taken on entry and `ERR_clear_last_mark` on **both** exits, so the
//! queue's mark state is balanced whatever happens. The one place that moves the mark is
//! the recoverable `ASN1_R_TOO_LONG` above, which pops to the mark and immediately takes
//! a new one.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};

use crate::asn1::d2i::ASN1_item_d2i_ex;
use crate::asn1::der::ASN1_get_object;
use crate::asn1::layout::{Asn1Item, D2iOfVoid};
use crate::ffi::guard_ffi;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::iolib::{BIO_ctrl, BIO_read};
use crate::runtime::bio::sys::FILE;
use crate::runtime::bio::{BIO_free, BIO_new, Bio, BIO_NOCLOSE};
use crate::runtime::buffer::{BUF_MEM_free, BUF_MEM_grow_clean, BUF_MEM_new, BufMem};
use crate::runtime::err::err_reasons::ASN1_R_TOO_LONG;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::err::{peek_last_reason, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};

/// `HEADER_SIZE` — the shortest possible header, a one-byte tag and a one-byte length.
const HEADER_SIZE: usize = 2;

/// `ASN1_CHUNK_INITIAL_SIZE` — how much of a declared length is read at a time.
///
/// The chunk is doubled as it goes, so a large object costs logarithmically many
/// allocations rather than one of the whole declared length — which is the point: a
/// hostile header claiming a gigabyte must not make this allocate a gigabyte before it
/// has any of it.
const ASN1_CHUNK_INITIAL_SIZE: usize = 16 * 1024;

/// `BIO_C_SET_FILE_PTR` — the ctrl that `BIO_set_fp` is a macro for.
const BIO_C_SET_FILE_PTR: c_int = 106;

/// Wrap a `FILE *` in a file BIO, run `f`, and free it.
///
/// As `a_i2d_fp`'s `with_file_bio`, including the discarded `BIO_ctrl` result and the
/// `BIO_NOCLOSE` flag: the caller owns the `FILE`.
///
/// # Safety
///
/// `in_` must be a live `FILE *` and `run` must accept the BIO it is given.
unsafe fn with_file_bio(
    in_: *mut FILE,
    site: &err_sites::ErrSite,
    run: impl FnOnce(*mut Bio) -> *mut c_void,
) -> *mut c_void {
    // SAFETY: `BIO_s_file()` answers a static method.
    let b = unsafe { BIO_new(BIO_s_file()) };
    if b.is_null() {
        // SAFETY: the site is the caller's compile-time constant.
        unsafe { raise_site(site) };
        return core::ptr::null_mut();
    }
    // SAFETY: `b` is the BIO just made and `in_` is the caller's live `FILE`.
    unsafe {
        BIO_ctrl(
            b,
            BIO_C_SET_FILE_PTR,
            c_long::from(BIO_NOCLOSE),
            in_.cast::<c_void>(),
        )
    };
    let ret = run(b);
    // SAFETY: `b` is this call's BIO and the caller still owns the `FILE`.
    unsafe { BIO_free(b) };
    ret
}

/// `void *ASN1_d2i_fp(void *(*xnew)(void), d2i_of_void *d2i, FILE *in, void **x)`
///
/// `xnew` is **never called** — not here and not in the authority. It survives in the
/// signature because the 0.9.6-era API took it, and it is kept because a caller passing a
/// function pointer is part of the observable interface even though the pointer is
/// ignored.
///
/// # Safety
///
/// `d2i` must be a live decoder matching `x`; `in_` must be a live `FILE *`; `x` must be
/// writable for a `void *`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_d2i_fp(
    xnew: unsafe extern "C" fn() -> *mut c_void,
    d2i: D2iOfVoid,
    in_: *mut FILE,
    x: *mut *mut c_void,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // The authority never calls it; the binding is what keeps the arity right.
        let _ = xnew;
        // SAFETY: `in_` is the caller's `FILE`.
        unsafe {
            with_file_bio(in_, &err_sites::A_D2I_FP_28, |b| {
                ASN1_d2i_bio(xnew, d2i, b, x)
            })
        }
    })
}

/// `void *ASN1_d2i_bio(void *(*xnew)(void), d2i_of_void *d2i, BIO *in, void **x)`
///
/// Reads one object with [`asn1_d2i_read_bio`] and hands its bytes to the caller's
/// decoder. The buffer is released on **both** paths — including the failure of the
/// decode, which a caller cannot tell apart from "no object here" because both answer
/// null.
///
/// # Safety
///
/// As [`ASN1_d2i_fp`]; `in_` must be a live BIO.
#[no_mangle]
pub unsafe extern "C" fn ASN1_d2i_bio(
    xnew: unsafe extern "C" fn() -> *mut c_void,
    d2i: D2iOfVoid,
    in_: *mut Bio,
    x: *mut *mut c_void,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        let _ = xnew;
        let mut b: *mut BufMem = core::ptr::null_mut();
        // SAFETY: `in_` is the caller's live BIO and `b` is a null slot.
        let len = unsafe { asn1_d2i_read_bio(in_, &mut b) };
        let ret = if len < 0 {
            core::ptr::null_mut()
        } else {
            // SAFETY: `b` is the buffer the read just filled.
            let data = unsafe { (*b).data }.cast::<c_uchar>();
            let mut p: *const c_uchar = data;
            // SAFETY: `data` holds `len` bytes and `d2i` is the caller's decoder.
            unsafe { d2i(x, &mut p, c_long::from(len)) }
        };
        // SAFETY: `b` is this call's buffer or null, and the decode has copied what it
        // needs out of it.
        unsafe { BUF_MEM_free(b) };
        ret
    })
}

/// `void *ASN1_item_d2i_bio_ex(const ASN1_ITEM *it, BIO *in, void *x,
/// OSSL_LIB_CTX *libctx, const char *propq)`
///
/// A null `in` is refused **before** the read, which is the difference between a caller
/// mistake and a stream that holds nothing.
///
/// # Safety
///
/// `it` must be a live item; `in_` must be a live BIO; `x` must be null or a live value
/// slot; `libctx` must be null or live and `propq` null or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_d2i_bio_ex(
    it: *const Asn1Item,
    in_: *mut Bio,
    x: *mut c_void,
    libctx: *mut c_void,
    propq: *const core::ffi::c_char,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        if in_.is_null() {
            return core::ptr::null_mut();
        }
        let mut b: *mut BufMem = core::ptr::null_mut();
        // SAFETY: `in_` is the caller's live BIO.
        let len = unsafe { asn1_d2i_read_bio(in_, &mut b) };
        let ret = if len < 0 {
            core::ptr::null_mut()
        } else {
            // SAFETY: `b` is the buffer the read just filled.
            let data = unsafe { (*b).data }.cast::<c_uchar>();
            let mut p: *const c_uchar = data;
            // SAFETY: `data` holds `len` bytes.
            unsafe {
                ASN1_item_d2i_ex(
                    x.cast::<*mut c_void>(),
                    &mut p,
                    c_long::from(len),
                    it,
                    libctx,
                    propq,
                )
            }
        };
        // SAFETY: `b` is this call's buffer or null.
        unsafe { BUF_MEM_free(b) };
        ret
    })
}

/// `void *ASN1_item_d2i_bio(const ASN1_ITEM *it, BIO *in, void *x)`
///
/// # Safety
///
/// As [`ASN1_item_d2i_bio_ex`], without the context arguments.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_d2i_bio(
    it: *const Asn1Item,
    in_: *mut Bio,
    x: *mut c_void,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: the caller's contract passes through unchanged.
        unsafe { ASN1_item_d2i_bio_ex(it, in_, x, core::ptr::null_mut(), core::ptr::null()) }
    })
}

/// `void *ASN1_item_d2i_fp_ex(const ASN1_ITEM *it, FILE *in, void *x,
/// OSSL_LIB_CTX *libctx, const char *propq)`
///
/// # Safety
///
/// `it` must be a live item; `in_` must be a live `FILE *`; `x` must be null or a live
/// value slot; `libctx` must be null or live and `propq` null or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_d2i_fp_ex(
    it: *const Asn1Item,
    in_: *mut FILE,
    x: *mut c_void,
    libctx: *mut c_void,
    propq: *const core::ffi::c_char,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `in_` is the caller's `FILE`.
        unsafe {
            with_file_bio(in_, &err_sites::A_D2I_FP_92, |b| {
                ASN1_item_d2i_bio_ex(it, b, x, libctx, propq)
            })
        }
    })
}

/// `void *ASN1_item_d2i_fp(const ASN1_ITEM *it, FILE *in, void *x)`
///
/// # Safety
///
/// As [`ASN1_item_d2i_fp_ex`], without the context arguments.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_d2i_fp(
    it: *const Asn1Item,
    in_: *mut FILE,
    x: *mut c_void,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: the caller's contract passes through unchanged.
        unsafe { ASN1_item_d2i_fp_ex(it, in_, x, core::ptr::null_mut(), core::ptr::null()) }
    })
}

/// `int asn1_d2i_read_bio(BIO *in, BUF_MEM **pb)`
///
/// Reads one complete top-level DER object, growing `*pb` to hold it, and answers its
/// length — or `-1` after raising. See the module documentation for the two decisions
/// that make this more than a loop: the recoverable `ASN1_R_TOO_LONG`, and the quiet EOF.
///
/// # Safety
///
/// `in_` must be a live BIO; `pb` must be a live slot.
#[no_mangle]
pub unsafe extern "C" fn asn1_d2i_read_bio(in_: *mut Bio, pb: *mut *mut BufMem) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: `BUF_MEM_new` zero-allocates and takes a file/line for the mdbg record.
        let b = BUF_MEM_new();
        if b.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_D2I_FP_125) };
            return -1;
        }

        let mut want: usize = HEADER_SIZE;
        let mut eos: u32 = 0;
        let mut off: usize = 0;
        let mut len: usize = 0;

        // The queue's mark cursor is process-thread-local and the call takes no
        // arguments, so there is nothing to state a precondition about.
        ERR_set_mark();

        // The authority's `for (;;)` with five `continue`s and one `break`; spelled as a
        // labelled loop so each exit is explicit.
        let outcome: c_int = 'outer: loop {
            let mut diff = len.wrapping_sub(off);
            if want >= diff {
                // Not enough bytes buffered for what the header needs: read the rest.
                want -= diff;

                let grew = if len.checked_add(want).is_none() {
                    false
                } else {
                    // SAFETY: `b` is this call's live buffer and `len + want` was just
                    // established to fit.
                    (unsafe { BUF_MEM_grow_clean(b, len + want) }) != 0
                };
                if !grew {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::A_D2I_FP_138) };
                    break 'outer -1;
                }
                // SAFETY: `b` has room for `want` more bytes at `len`.
                let i = unsafe { BIO_read(in_, buffer_dest(b, len), want as c_int) };
                if i <= 0 {
                    // A read failure, an EOF with bytes already buffered, or an EOF
                    // still owing an end-of-contents marker are all truncation. A clean
                    // EOF at a top-level boundary is the normal end of input and raises
                    // nothing — see the module documentation.
                    if i < 0 || diff != 0 || eos != 0 {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::A_D2I_FP_156) };
                    }
                    break 'outer -1;
                }
                let i = i as usize;
                if len.checked_add(i).is_none() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::A_D2I_FP_161) };
                    break 'outer -1;
                }
                len += i;
                if i < want {
                    continue;
                }
            }
            // else the data is already loaded

            // There must be room for a complete header.
            // SAFETY: `b` holds `len` bytes and `off <= len` here.
            let mut q = unsafe { buffer_dest(b, off) }.cast::<u8>();
            let p = q;
            diff = len - off;
            if diff < 2 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::A_D2I_FP_177) };
                break 'outer -1;
            }

            diff -= 1;
            // A multi-byte tag: find out whether all of it has arrived. The tag byte
            // itself is consumed here whether or not a continuation follows, because
            // the authority's condition is `(*(q++) & 0x1f) == 0x1f`.
            // SAFETY: `q` is readable for the byte the `diff >= 2` check left.
            let tag_byte = unsafe { *q };
            // SAFETY: as above; the increment stays inside the buffer because `diff >= 1`.
            q = unsafe { q.add(1) };
            if (tag_byte & TAG_NUMBER_MASK) == TAG_NUMBER_MASK {
                let mut i = 0u32;
                loop {
                    if i > 4 {
                        // The tag must fit an `int`.
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::A_D2I_FP_188) };
                        break 'outer -1;
                    }
                    i += 1;
                    diff -= 1;
                    // The authority's `while (diff > 0 && *(q++) & 0x80)`: the byte is
                    // read *and* consumed only when `diff > 0`, which is why the `*q`
                    // in the `diff == 0` branch below reads a byte this loop did not
                    // consume.
                    if diff == 0 {
                        break;
                    }
                    // SAFETY: `diff > 0` means `q` is still inside the buffer.
                    let b = unsafe { *q };
                    // SAFETY: as above.
                    q = unsafe { q.add(1) };
                    if (b & 0x80) == 0 {
                        break;
                    }
                }

                if diff == 0 {
                    // End of the current data: at least one more byte is needed for the
                    // length, and two if the tag is still incomplete.
                    // SAFETY: `q` points at a byte the loop above did not consume.
                    let still_long = (unsafe { *q } & 0x80) != 0;
                    // SAFETY: `q` and `p` are both inside this call's buffer, and `q`
                    // has not moved before `p`.
                    let consumed = unsafe { q.offset_from(p) } as usize;
                    want = consumed + 2;
                    if still_long {
                        want += 1;
                    }
                    continue;
                }
            }

            // Check the length. This also covers the indefinite-length form.
            diff -= 1;
            // SAFETY: `q` is readable.
            if (unsafe { *q } & 0x80) != 0 {
                // SAFETY: `q` is readable.
                let i = (unsafe { *q } & 0x7f) as usize;
                if i > core::mem::size_of::<c_long>() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::A_D2I_FP_214) };
                    break 'outer -1;
                }
                if i > diff {
                    // SAFETY: `q` and `p` are both inside this call's buffer.
                    let consumed = unsafe { q.offset_from(p) } as usize;
                    want = consumed + i + 1;
                    continue;
                }
            }

            // The header is complete. Parse it.
            q = p;
            diff = len - off;
            let mut slen: c_long = 0;
            let mut tag: c_int = 0;
            let mut xclass: c_int = 0;
            let mut qc: *const c_uchar = q;
            // SAFETY: `qc` is readable for `diff` bytes.
            let inf = unsafe {
                ASN1_get_object(&mut qc, &mut slen, &mut tag, &mut xclass, diff as c_long)
            };
            q = qc.cast_mut();
            if inf & 0x80 != 0 {
                // The one recoverable failure: the declared length needs more bytes than
                // the buffer has. The reason is popped and the mark replaced, so a stream
                // arriving in pieces does not accumulate errors.
                // SAFETY: no arguments.
                let reason = peek_last_reason();
                if reason != ASN1_R_TOO_LONG as core::ffi::c_ulong {
                    break 'outer -1;
                }
                // The queue's mark cursor is process-thread-local and the call takes no
                // arguments, so there is nothing to state a precondition about.
                ERR_pop_to_mark();
                // The queue's mark cursor is process-thread-local and the call takes no
                // arguments, so there is nothing to state a precondition about.
                ERR_set_mark();
            }
            // SAFETY: `q` and `p` are both inside this call's buffer.
            off += unsafe { q.offset_from(p) } as usize;

            if inf & 1 != 0 {
                // Constructed with no body of its own: read another header.
                if eos == u32::MAX {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::A_D2I_FP_244) };
                    break 'outer -1;
                }
                eos += 1;
                want = HEADER_SIZE;
            } else if eos != 0 && slen == 0 && tag == V_ASN1_EOC {
                // An end-of-contents marker closes one level.
                eos -= 1;
                if eos == 0 {
                    break 'outer 0;
                }
                want = HEADER_SIZE;
            } else {
                // Absorb `slen` bytes of content. `want` is mutated below but `slen` is
                // what `off` advances by, so the two are kept apart deliberately.
                want = slen.max(0) as usize;
                if want > len - off {
                    let mut chunk_max = ASN1_CHUNK_INITIAL_SIZE;
                    want -= len - off;
                    if want > c_int::MAX as usize || len.checked_add(want).is_none() {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::A_D2I_FP_264) };
                        break 'outer -1;
                    }
                    while want > 0 {
                        // In chunks of increasing size, so an over-large declared length
                        // is caught by EOF rather than by one enormous allocation.
                        let chunk = if want > chunk_max { chunk_max } else { want };
                        // SAFETY: `b` is this call's live buffer.
                        if unsafe { BUF_MEM_grow_clean(b, len + chunk) } == 0 {
                            // SAFETY: a compile-time-constant site.
                            unsafe { raise_site(&err_sites::A_D2I_FP_278) };
                            break 'outer -1;
                        }
                        want -= chunk;
                        let mut remaining = chunk;
                        while remaining > 0 {
                            // SAFETY: `b` has room for `chunk` bytes at `len`.
                            let i =
                                unsafe { BIO_read(in_, buffer_dest(b, len), remaining as c_int) };
                            if i <= 0 {
                                // SAFETY: a compile-time-constant site.
                                unsafe { raise_site(&err_sites::A_D2I_FP_285) };
                                break 'outer -1;
                            }
                            let i = i as usize;
                            len += i;
                            remaining -= i;
                        }
                        if chunk_max < (c_int::MAX as usize) / 2 {
                            chunk_max *= 2;
                        }
                    }
                }
                // The authority's `off + slen < off` catches both a negative `slen`
                // and a sum that does not fit.
                if off.checked_add(slen.max(0) as usize).is_none() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::A_D2I_FP_300) };
                    break 'outer -1;
                }
                off += slen.max(0) as usize;
                if eos == 0 {
                    break 'outer 0;
                }
                want = HEADER_SIZE;
            }
        };

        if outcome != 0 {
            // The queue's mark cursor is process-thread-local and the call takes no
            // arguments, so there is nothing to state a precondition about.
            ERR_clear_last_mark();
            // SAFETY: `b` is this call's buffer.
            unsafe { BUF_MEM_free(b) };
            return -1;
        }
        if off > c_int::MAX as usize {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_D2I_FP_312) };
            // The queue's mark cursor is process-thread-local and the call takes no
            // arguments, so there is nothing to state a precondition about.
            ERR_clear_last_mark();
            // SAFETY: `b` is this call's buffer.
            unsafe { BUF_MEM_free(b) };
            return -1;
        }

        // SAFETY: `pb` is the caller's live slot.
        unsafe { *pb = b };
        // The queue's mark cursor is process-thread-local and the call takes no
        // arguments, so there is nothing to state a precondition about.
        ERR_clear_last_mark();
        off as c_int
    })
}

/// The writable address `len` bytes into a buffer, without an `unsafe` block at each
/// call site.
///
/// `wrapping_add` rather than `add` because the offset is established by the caller's own
/// `BUF_MEM_grow_clean` a few lines above, and a wrapping add cannot be the thing that
/// panics in a debug build where the authority would have wrapped.
///
/// # Safety
///
/// `b` must be a live `BUF_MEM` whose allocation covers `len` bytes.
unsafe fn buffer_dest(b: *mut BufMem, len: usize) -> *mut c_void {
    // SAFETY: the caller's contract.
    let data = unsafe { (*b).data };
    data.cast::<u8>().wrapping_add(len).cast::<c_void>()
}

/// The bits of a tag byte that mean "the tag number continues in the next byte".
const TAG_NUMBER_MASK: u8 = 0x1f;
/// `V_ASN1_EOC` — the tag an end-of-contents marker carries.
const V_ASN1_EOC: c_int = 0;
