//! Phase 4 — the memory BIO (`BIO_s_mem`, `BIO_s_secmem`, `BIO_s_readbuffer`,
//! `BIO_new_mem_buf`).
//!
//! The memory BIO is the most-used BIO in the library: it is how an application
//! hands a blob to a parser, how a parser hands back a result, and how provider
//! parameter and key encoders exchange data. Its observable surface is unusually
//! wide for something called "memory":
//!
//! * the read pointer and the write pointer are **separate `BUF_MEM` headers over
//!   one allocation**, so `BIO_get_mem_ptr` and `BIO_get_mem_data` can disagree;
//! * `BIO_reset` zeroes the buffer unless `BIO_FLAGS_NONCLEAR_RST` is set, and a
//!   read-only BIO instead rewinds its header — a genuinely different operation;
//! * `BIO_seek`/`BIO_tell` move within the *current* window and refuse to leave
//!   it (`-1` past the ends);
//! * reading from an empty buffer returns `bio->num` (default `-1`), setting the
//!   retry-read flag only when that value is non-zero;
//! * writing to a `BIO_FLAGS_MEM_RDONLY` BIO raises
//!   `BIO_R_WRITE_TO_READ_ONLY_BIO` and fails;
//! * `BIO_ctrl(BIO_C_SET_BUF_MEM_STATE…)` is absent, but `BIO_C_SET_BUF_MEM`
//!   takes over an externally supplied `BUF_MEM` and `BIO_C_GET_BUF_MEM_PTR`
//!   hands the internal one out.
//!
//! Every one of those is measured by `courts/phase4/rt_bio_mem_probe.c` against
//! the authority, not inferred from the header.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::buffer::{BufMem, BUF_MEM_FLAG_SECURE};
use crate::runtime::err::err_sites::{BSS_MEM_221, BSS_MEM_228, BSS_MEM_90};
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

use super::method::{bread_conv, bwrite_conv};
use super::{
    Bio, BioMethod, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_GET_CLOSE, BIO_CTRL_INFO,
    BIO_CTRL_PENDING, BIO_CTRL_POP, BIO_CTRL_PUSH, BIO_CTRL_RESET, BIO_CTRL_SET_CLOSE,
    BIO_CTRL_WPENDING, BIO_C_FILE_SEEK, BIO_C_FILE_TELL, BIO_C_GET_BUF_MEM_PTR, BIO_C_SET_BUF_MEM,
    BIO_C_SET_BUF_MEM_EOF_RETURN, BIO_FLAGS_MEM_RDONLY, BIO_FLAGS_NONCLEAR_RST, BIO_TYPE_MEM,
};

/// The authority's `BIO_BUF_MEM`: two `BUF_MEM` headers over one allocation.
///
/// `buf` owns the allocation; `readp` is a header copy that tracks how far reads
/// have advanced. For a read-only BIO the roles are reversed in `mem_ctrl`, which
/// is why both are kept rather than a single cursor.
#[repr(C)]
pub struct BioBufMem {
    /// The allocated buffer (the authority's `bb->buf`).
    pub buf: *mut BufMem,
    /// The read pointer header (the authority's `bb->readp`).
    pub readp: *mut BufMem,
}

/// The method name the authority reports for a memory buffer.
const MEM_NAME: &[u8] = b"memory buffer\0";
/// The method name the authority reports for a secure memory buffer.
const SECMEM_NAME: &[u8] = b"secure memory buffer\0";

/// `BIO_TYPE_MEM` is `1 | BIO_TYPE_SOURCE_SINK`; the constant is reused here so
/// the table cannot drift from the header.
const MEM_TYPE: c_int = BIO_TYPE_MEM;
/// The secure buffer shares the memory type, as the authority's table does.
const SECMEM_TYPE: c_int = BIO_TYPE_MEM;

/// A compiled-in method table. `BIO_s_mem()` returns its address.
static MEM_METHOD: BioMethod = BioMethod {
    type_: MEM_TYPE,
    name: MEM_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(mem_write),
    bread: Some(bread_conv),
    bread_old: Some(mem_read),
    bputs: Some(mem_puts),
    bgets: Some(mem_gets),
    ctrl: Some(mem_ctrl),
    create: Some(mem_new),
    destroy: Some(mem_free),
    callback_ctrl: None,
    sendmmsg: None,
    recvmmsg: None,
};

/// A compiled-in method table for the secure memory buffer.
static SECMEM_METHOD: BioMethod = BioMethod {
    type_: SECMEM_TYPE,
    name: SECMEM_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(mem_write),
    bread: Some(bread_conv),
    bread_old: Some(mem_read),
    bputs: Some(mem_puts),
    bgets: Some(mem_gets),
    ctrl: Some(mem_ctrl),
    create: Some(secmem_new),
    destroy: Some(mem_free),
    callback_ctrl: None,
    sendmmsg: None,
    recvmmsg: None,
};

/// `const BIO_METHOD *BIO_s_mem(void)`
#[no_mangle]
pub extern "C" fn BIO_s_mem() -> *const BioMethod {
    guard_ffi(ptr::null(), || &MEM_METHOD)
}

/// `const BIO_METHOD *BIO_s_secmem(void)`
///
/// The method is the same code path with `BUF_MEM_FLAG_SECURE` set at creation,
/// so a single `mem_write` serves both and only the allocation differs.
#[no_mangle]
pub extern "C" fn BIO_s_secmem() -> *const BioMethod {
    guard_ffi(ptr::null(), || &SECMEM_METHOD)
}

/// `BIO *BIO_new_mem_buf(const void *buf, int len)`
///
/// A negative `len` means "the buffer is NUL-terminated, measure it"; the result
/// is a read-only memory BIO whose `num` (the empty-read return value) is 0, so a
/// read past the end reports EOF rather than a retryable failure.
///
/// # Safety
/// `buf` must be NULL or readable: for `len >= 0`, for `len` bytes; for a
/// negative `len`, as a NUL-terminated string. A NULL `buf` is rejected.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        if buf.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BSS_MEM_90) };
            return ptr::null_mut();
        }
        let sz = if len < 0 {
            // SAFETY: a negative `len` promises a NUL-terminated string.
            unsafe { super::sys::strlen(buf.cast()) }
        } else {
            len as usize
        };
        // SAFETY: `BIO_new` allocates and runs the method's `create`.
        let ret = unsafe { super::BIO_new(BIO_s_mem()) };
        if ret.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ret` is a freshly created memory BIO, so `ptr` is the
        // `BioBufMem` installed by `mem_new`.
        unsafe {
            let bb = (*ret).ptr.cast::<BioBufMem>();
            let b = (*bb).buf;
            (*b).data = buf.cast_mut().cast();
            (*b).length = sz;
            (*b).max = sz;
            *(*bb).readp = *b;
            (*ret).flags |= BIO_FLAGS_MEM_RDONLY;
            // Static data does not become readable by retrying.
            (*ret).num = 0;
        }
        ret
    })
}

/// The authority's `static int mem_init(BIO *bi, unsigned long flags)`.
///
/// # Safety
/// `bi` must be a live BIO whose `ptr` is not yet used by this method.
unsafe fn mem_init(bi: *mut Bio, flags: core::ffi::c_ulong) -> c_int {
    // `CRYPTO_zalloc` and `BUF_MEM_new_ex` are safe entry points; no `unsafe`
    // block is needed to call them, and the previous `unsafe` markers here were
    // noise that the lints correctly flagged.
    let bb = CRYPTO_zalloc(core::mem::size_of::<BioBufMem>(), ptr::null(), 0).cast::<BioBufMem>();
    if bb.is_null() {
        return 0;
    }
    let buf = crate::runtime::buffer::BUF_MEM_new_ex(flags);
    if buf.is_null() {
        // SAFETY: `bb` is owned here and not yet published.
        unsafe { CRYPTO_free(bb.cast(), ptr::null(), 0) };
        return 0;
    }
    let readp = CRYPTO_zalloc(core::mem::size_of::<BufMem>(), ptr::null(), 0).cast::<BufMem>();
    if readp.is_null() {
        // SAFETY: neither allocation is published yet.
        unsafe {
            crate::runtime::buffer::BUF_MEM_free(buf);
            CRYPTO_free(bb.cast(), ptr::null(), 0);
        }
        return 0;
    }
    // SAFETY: `readp` is a fresh header; `buf` is live.
    unsafe {
        *readp = *buf;
        (*bb).buf = buf;
        (*bb).readp = readp;
        (*bi).shutdown = 1;
        (*bi).init = 1;
        (*bi).num = -1;
        (*bi).ptr = bb.cast();
    }
    1
}

/// `static int mem_new(BIO *bi)`
///
/// # Safety
/// `bi` must be a live BIO.
unsafe extern "C" fn mem_new(bi: *mut Bio) -> c_int {
    // SAFETY: forwarded; `mem_init` allocates and installs the method data.
    unsafe { mem_init(bi, 0) }
}

/// `static int secmem_new(BIO *bi)`
///
/// # Safety
/// `bi` must be a live BIO.
unsafe extern "C" fn secmem_new(bi: *mut Bio) -> c_int {
    // SAFETY: as for `mem_new`.
    unsafe { mem_init(bi, BUF_MEM_FLAG_SECURE) }
}

/// `static int mem_buf_free(BIO *a)`
///
/// # Safety
/// `a` must be NULL or a live memory BIO.
unsafe fn mem_buf_free(a: *mut Bio) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: `a` is non-NULL; a memory BIO's `ptr` is a `BioBufMem`.
    unsafe {
        if (*a).shutdown != 0 && (*a).init != 0 && !(*a).ptr.is_null() {
            let bb = (*a).ptr.cast::<BioBufMem>();
            let b = (*bb).buf;
            if (*a).flags & BIO_FLAGS_MEM_RDONLY != 0 {
                // The data belongs to the caller; the buffer must not free it.
                (*b).data = ptr::null_mut();
            }
            crate::runtime::buffer::BUF_MEM_free(b);
        }
    }
    1
}

/// `static int mem_free(BIO *a)`
///
/// # Safety
/// `a` must be a live memory BIO being destroyed.
unsafe extern "C" fn mem_free(a: *mut Bio) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: `a` is non-NULL; the method's own data is a `BioBufMem`.
    unsafe {
        let bb = (*a).ptr.cast::<BioBufMem>();
        if mem_buf_free(a) == 0 {
            return 0;
        }
        CRYPTO_free((*bb).readp.cast(), ptr::null(), 0);
        CRYPTO_free(bb.cast(), ptr::null(), 0);
    }
    1
}

/// The authority's `static int mem_buf_sync(BIO *b)`.
///
/// # Safety
/// `b` must be NULL or a live memory BIO.
unsafe fn mem_buf_sync(b: *mut Bio) -> c_int {
    // SAFETY: `b` is NULL or a live memory BIO per the caller's contract; `as_ref`
    // makes a NULL argument a no-op rather than a dereference.
    if let Some(b) = unsafe { b.as_ref() } {
        if b.init != 0 && !b.ptr.is_null() {
            // SAFETY: `ptr` is a `BioBufMem` for this method.
            unsafe {
                let bbm = b.ptr.cast::<BioBufMem>();
                if (*(*bbm).readp).data != (*(*bbm).buf).data {
                    ptr::copy_nonoverlapping(
                        (*(*bbm).readp).data,
                        (*(*bbm).buf).data,
                        (*(*bbm).readp).length,
                    );
                    (*(*bbm).buf).length = (*(*bbm).readp).length;
                    (*(*bbm).readp).data = (*(*bbm).buf).data;
                }
            }
        }
    }
    0
}

/// `static int mem_read(BIO *b, char *out, int outl)`
///
/// # Safety
/// `b` must be a live memory BIO; `out` must be valid for `outl` bytes.
unsafe extern "C" fn mem_read(b: *mut Bio, out: *mut c_char, outl: c_int) -> c_int {
    // SAFETY: the dispatch layer only calls this with a live BIO of this method.
    let (bbm, flags) = unsafe { ((*b).ptr.cast::<BioBufMem>(), (*b).flags) };
    // SAFETY: `bbm` is this method's data.
    let bm = if flags & BIO_FLAGS_MEM_RDONLY != 0 {
        // SAFETY: `bbm` is live and `buf` is its owned header.
        unsafe { (*bbm).buf }
    } else {
        // SAFETY: `bbm` is live and `readp` is its read-cursor header.
        unsafe { (*bbm).readp }
    };
    // SAFETY: `b` is live.
    unsafe { super::BIO_clear_flags(b, super::BIO_FLAGS_RWS | super::BIO_FLAGS_SHOULD_RETRY) };
    // SAFETY: `bm` is a live header.
    let mut ret: c_int = unsafe {
        if outl >= 0 && (outl as usize) > (*bm).length {
            (*bm).length as c_int
        } else {
            outl
        }
    };
    // SAFETY: `bm` is live; the read pointer and length bound the copy.
    unsafe {
        if !out.is_null() && ret > 0 {
            ptr::copy_nonoverlapping((*bm).data, out, ret as usize);
            (*bm).length -= ret as usize;
            (*bm).max -= ret as usize;
            (*bm).data = (*bm).data.add(ret as usize);
        } else if (*bm).length == 0 {
            ret = (*b).num;
            if ret != 0 {
                super::BIO_set_flags(b, super::BIO_FLAGS_READ | super::BIO_FLAGS_SHOULD_RETRY);
            }
        }
    }
    ret
}

/// `static int mem_write(BIO *b, const char *in, int inl)`
///
/// # Safety
/// `b` must be a live memory BIO; `in` must be valid for `inl` bytes.
unsafe extern "C" fn mem_write(b: *mut Bio, in_: *const c_char, inl: c_int) -> c_int {
    let mut ret: c_int = -1;
    // SAFETY: the dispatch layer only calls this with a live BIO of this method.
    let bbm = unsafe { (*b).ptr.cast::<BioBufMem>() };
    // SAFETY: `b` is live.
    if unsafe { (*b).flags } & BIO_FLAGS_MEM_RDONLY != 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_MEM_221) };
        return ret;
    }
    // SAFETY: `b` is live; the retry flags are part of its state.
    unsafe { super::BIO_clear_flags(b, super::BIO_FLAGS_RWS | super::BIO_FLAGS_SHOULD_RETRY) };
    if inl == 0 {
        return 0;
    }
    if in_.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_MEM_228) };
        return ret;
    }
    // SAFETY: `bbm` is live.
    let blen = unsafe { (*(*bbm).readp).length };
    // SAFETY: `b` is live.
    unsafe { mem_buf_sync(b) };
    // SAFETY: `bbm` is live and both lengths are consistent.
    let grew = unsafe {
        let newlen = blen + inl as usize;
        crate::runtime::buffer::BUF_MEM_grow_clean((*bbm).buf, newlen)
    };
    if grew == 0 {
        return ret;
    }
    // SAFETY: `in` is valid for `inl` bytes and the destination was grown by
    // `blen + inl` bytes.
    unsafe {
        ptr::copy_nonoverlapping(in_, (*(*bbm).buf).data.add(blen), inl as usize);
        *(*bbm).readp = *(*bbm).buf;
    }
    ret = inl;
    ret
}

/// `static long mem_ctrl(BIO *b, int cmd, long num, void *ptr)`
///
/// # Safety
/// `b` must be a live memory BIO; `arg` must be as the command requires.
unsafe extern "C" fn mem_ctrl(b: *mut Bio, cmd: c_int, num: c_long, arg: *mut c_void) -> c_long {
    let mut ret: c_long = 1;
    // SAFETY: the dispatch layer only calls this with a live BIO of this method.
    let bbm = unsafe { (*b).ptr.cast::<BioBufMem>() };
    // SAFETY: `b` is live.
    let flags = unsafe { (*b).flags };
    // SAFETY: `bbm` is live for every command below.
    let (mut bm, bo) = unsafe {
        if flags & BIO_FLAGS_MEM_RDONLY != 0 {
            ((*bbm).buf, (*bbm).readp)
        } else {
            ((*bbm).readp, (*bbm).buf)
        }
    };
    // SAFETY: `bm` and `bo` are live headers.
    let mut off: isize = unsafe {
        if (*bm).data == (*bo).data {
            0
        } else {
            (*bm).data.offset_from((*bo).data)
        }
    };
    // SAFETY: `bm` is live.
    let remain: isize = unsafe { (*bm).length as isize };

    match cmd {
        BIO_CTRL_RESET => {
            // SAFETY: `bbm` is live.
            unsafe {
                bm = (*bbm).buf;
                if !(*bm).data.is_null() {
                    if flags & BIO_FLAGS_MEM_RDONLY == 0 {
                        if flags & BIO_FLAGS_NONCLEAR_RST == 0 {
                            ptr::write_bytes((*bm).data.cast::<u8>(), 0, (*bm).max);
                            (*bm).length = 0;
                        }
                        *(*bbm).readp = *(*bbm).buf;
                    } else {
                        // A read-only BIO only rewinds its header.
                        *(*bbm).buf = *(*bbm).readp;
                    }
                }
            }
        }
        BIO_C_FILE_SEEK => {
            // SAFETY: `bm` and `bo` are live; the bounds check keeps the pointer
            // arithmetic inside the allocation.
            let ok = num >= 0 && (num as isize) <= off + remain;
            if !ok {
                return -1;
            }
            // SAFETY: `bo->data` is the allocation base and `num` is in range.
            unsafe {
                (*bm).data = if num != 0 {
                    (*bo).data.add(num as usize)
                } else {
                    (*bo).data
                };
                (*bm).length = (*bo).length - num as usize;
                (*bm).max = (*bo).max - num as usize;
            }
            off = num as isize;
            ret = if (off as i64) > c_long::MAX {
                -1
            } else {
                off as c_long
            };
        }
        BIO_C_FILE_TELL => {
            ret = if (off as i64) > c_long::MAX {
                -1
            } else {
                off as c_long
            };
        }
        BIO_CTRL_EOF => {
            // SAFETY: `bm` is live.
            ret = unsafe { ((*bm).length == 0) as c_long };
        }
        BIO_C_SET_BUF_MEM_EOF_RETURN => {
            // SAFETY: `b` is live.
            unsafe { (*b).num = num as c_int };
        }
        BIO_CTRL_INFO => {
            // SAFETY: `bm` is live.
            ret = unsafe { (*bm).length as c_long };
            if !arg.is_null() {
                // SAFETY: the caller passes `char **` for `BIO_CTRL_INFO`.
                unsafe { *arg.cast::<*mut c_char>() = (*bm).data };
            }
        }
        BIO_C_SET_BUF_MEM => {
            // SAFETY: `b` is live.
            unsafe { mem_buf_free(b) };
            // SAFETY: `b` is live; `arg` is the caller's `BUF_MEM`.
            unsafe {
                (*b).shutdown = num as c_int;
                (*bbm).buf = arg.cast::<BufMem>();
                *(*bbm).readp = *(*bbm).buf;
            }
        }
        BIO_C_GET_BUF_MEM_PTR => {
            if !arg.is_null() {
                if flags & BIO_FLAGS_MEM_RDONLY == 0 {
                    // SAFETY: `b` is live.
                    unsafe { mem_buf_sync(b) };
                }
                // SAFETY: `bbm` is live; the caller passes `BUF_MEM **`.
                unsafe { *arg.cast::<*mut BufMem>() = (*bbm).buf };
            }
        }
        BIO_CTRL_GET_CLOSE => {
            // SAFETY: `b` is live.
            ret = unsafe { (*b).shutdown as c_long };
        }
        BIO_CTRL_SET_CLOSE => {
            // SAFETY: `b` is live.
            unsafe { (*b).shutdown = num as c_int };
        }
        BIO_CTRL_WPENDING => ret = 0,
        BIO_CTRL_PENDING => {
            // SAFETY: `bm` is live.
            ret = unsafe { (*bm).length as c_long };
        }
        BIO_CTRL_FLUSH => ret = 1,
        // The authority groups `BIO_CTRL_DUP` with `FLUSH`; both report success
        // without doing anything, and `mem_buf_sync` is not called.
        _ if cmd == super::BIO_CTRL_DUP => ret = 1,
        BIO_CTRL_PUSH | BIO_CTRL_POP => ret = 0,
        _ => ret = 0,
    }
    // `remain` and `bm` are read by the seek/tell arm above; keep the compiler
    // from treating the rebinding as dead.
    let _ = (off, remain);
    ret
}

/// `static int mem_gets(BIO *bp, char *buf, int size)`
///
/// # Safety
/// `bp` must be a live memory BIO; `buf` must be valid for `size` bytes.
unsafe extern "C" fn mem_gets(bp: *mut Bio, buf: *mut c_char, size: c_int) -> c_int {
    // SAFETY: the dispatch layer only calls this with a live BIO of this method.
    let bbm = unsafe { (*bp).ptr.cast::<BioBufMem>() };
    // SAFETY: `bp` is live.
    let bm = unsafe {
        if (*bp).flags & BIO_FLAGS_MEM_RDONLY != 0 {
            (*bbm).buf
        } else {
            (*bbm).readp
        }
    };
    // SAFETY: `bp` is live.
    unsafe { super::BIO_clear_flags(bp, super::BIO_FLAGS_RWS | super::BIO_FLAGS_SHOULD_RETRY) };
    // SAFETY: `bm` is live.
    let mut j = unsafe {
        if (*bm).length < c_int::MAX as usize {
            (*bm).length as c_int
        } else {
            c_int::MAX
        }
    };
    if size - 1 < j {
        j = size - 1;
    }
    if j <= 0 {
        // SAFETY: `buf` is valid for `size >= 1` bytes here.
        unsafe { *buf = 0 };
        return 0;
    }
    // SAFETY: `bm` is live and `j` bytes are readable from `data`.
    let mut i = 0;
    // SAFETY: `bm` is live and `j` bounds the scan, so each `data.add(i)` is within
    // the readable region while `i < j`.
    unsafe {
        while i < j {
            if *(*bm).data.add(i as usize) == b'\n' as c_char {
                i += 1;
                break;
            }
            i += 1;
        }
    }
    // SAFETY: `bp` is live and the method's read contract holds.
    let i = unsafe { mem_read(bp, buf, i) };
    if i > 0 {
        // SAFETY: `mem_read` wrote `i` bytes and left room for the terminator
        // because `i <= size - 1`.
        unsafe { *buf.add(i as usize) = 0 };
    }
    i
}

/// `static int mem_puts(BIO *bp, const char *str)`
///
/// # Safety
/// `bp` must be a live memory BIO; `str` must be NUL-terminated.
unsafe extern "C" fn mem_puts(bp: *mut Bio, str_: *const c_char) -> c_int {
    // SAFETY: `str` is NUL-terminated per the method contract.
    let n = unsafe { super::sys::strlen(str_) };
    if n > c_int::MAX as usize {
        return -1;
    }
    // SAFETY: `bp` is live and `str` is valid for `n` bytes.
    unsafe { mem_write(bp, str_, n as c_int) }
}
