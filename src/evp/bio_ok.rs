//! Phase 9 — `crypto/evp/bio_ok.c`, the `BIO_f_reliable` filter, the one Phase 7.5 row this
//! stratum was left holding.
//!
//! Source authority: `openssl-3.6.4-production`. The build profile is the admitted one:
//! `FIPS_MODULE` undefined, `NDEBUG` (so the one `assert` in `block_in` is `ossl_likely`'s
//! identity rather than an abort), and the host is little-endian, so `internal/endian.h`'s
//! `IS_LITTLE_ENDIAN` arm of `longswap` is the arm that is compiled.
//!
//! ## Why this unit is Phase 9's and not 7.5's
//!
//! `src/evp/bio_enc.rs`'s module doc records the withholding: 7.5 read this file and found that
//! `sig_out` (`crypto/evp/bio_ok.c:456`) reaches the random layer. It is one call —
//! `RAND_bytes(md_data, md_size)` — which overwrites the message-digest method's own state block
//! with a fresh random seed and writes the same bytes into the record: the per-stream salt the
//! format's header exists to carry. `RAND_bytes` is `rand.h`'s, it landed with this stratum
//! (`crate::rand::rand_lib::RAND_bytes`), and it is the only call in the unit that reaches the
//! random layer. `BIO_f_reliable` therefore lands here.
//!
//! Two further facts 7.5 measured are worth keeping where the code now is: `ok_ctrl`'s
//! `BIO_CTRL_FLUSH` arm marks the stream finished and *then* writes (`:354-374`), and `block_in`
//! refuses a block whose declared length exceeds `OK_BLOCK_SIZE` **or** whose
//! `tl + OK_BLOCK_BLOCK + md_size` would wrap `SIZE_MAX` (`:578`, `:581`) — two different refusals
//! behind the same `berr` label.
//!
//! ## Names
//!
//! Every export keeps the authority's C name; the authority's file-local static and its context
//! type are spelled the way this crate spells shared tables and types.
//!
//! | authority             | this file     |
//! | --------------------- | ------------- |
//! | `methods_ok` (static) | [`METHODS_OK`] |
//! | `BIO_OK_CTX`          | [`BioOkCtx`]  |
//!
//! ## The one export and the court that drives it
//!
//! `BIO_f_reliable`, the method accessor, is this unit's only export. It is driven — with
//! `EVP_CIPHER_CTX_rand_key` and `EVP_SealInit`, the random layer's other two consumers — by
//! `courts/phase9/rt_rand_users_probe.c` (RT-RAND-USERS), which a sibling task extends in the same
//! commit to push a record through the filter and read it back.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_get0_md,
    EVP_MD_CTX_get0_md_data, EVP_MD_CTX_new, EVP_MD_get_size, EvpMd, EvpMdCtx,
};
use crate::rand::rand_lib::RAND_bytes;
use crate::runtime::bio::method::{bread_conv, bwrite_conv};
use crate::runtime::bio::sys;
use crate::runtime::bio::{
    BIO_callback_ctrl, BIO_clear_flags, BIO_copy_next_retry, BIO_ctrl, BIO_get_data, BIO_get_init,
    BIO_read, BIO_set_data, BIO_set_init, BIO_test_flags, BIO_write,
};
use crate::runtime::bio::{
    Bio, BioInfoCb, BioMethod, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_INFO, BIO_CTRL_PENDING,
    BIO_CTRL_RESET, BIO_CTRL_WPENDING, BIO_C_DO_STATE_MACHINE, BIO_C_GET_MD, BIO_C_SET_MD,
    BIO_FLAGS_IO_SPECIAL, BIO_FLAGS_READ, BIO_FLAGS_SHOULD_RETRY, BIO_FLAGS_WRITE, BIO_TYPE_CIPHER,
};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_zalloc};

// ---------------------------------------------------------------------------------------------
// The unit's constants and its one allocation coordinate
// ---------------------------------------------------------------------------------------------

/// `crypto/evp/bio_ok.c`, as the authority's compiler spelled it.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/bio_ok.c".as_ptr();

/// `OK_BLOCK_SIZE` — `crypto/evp/bio_ok.c:94`.
const OK_BLOCK_SIZE: usize = 1024 * 4;
/// `OK_BLOCK_BLOCK` — `crypto/evp/bio_ok.c:95`.
const OK_BLOCK_BLOCK: usize = 4;
/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:34`.
const EVP_MAX_MD_SIZE: usize = 64;
/// `IOBS` — `crypto/evp/bio_ok.c:96`: `OK_BLOCK_SIZE + OK_BLOCK_BLOCK + 3 * EVP_MAX_MD_SIZE`.
const IOBS: usize = OK_BLOCK_SIZE + OK_BLOCK_BLOCK + 3 * EVP_MAX_MD_SIZE;
/// `WELLKNOWN` — `crypto/evp/bio_ok.c:97`, without the terminating NUL: the authority passes
/// `strlen(WELLKNOWN)` to both `EVP_DigestUpdate` sites.
const WELLKNOWN: &[u8] = b"The quick brown fox jumped over the lazy dog's back.";

// ---------------------------------------------------------------------------------------------
// `crypto/evp/bio_ok.c` — `BIO_f_reliable`
// ---------------------------------------------------------------------------------------------

/// `BIO_OK_CTX` — `crypto/evp/bio_ok.c:99-110`.
///
/// `buf` is `IOBS` bytes: a block's length and data half plus room for three digest halves, which
/// is what lets a record carry its salt, its digest and the start of its successor at once.
#[repr(C)]
struct BioOkCtx {
    /// `size_t buf_len`.
    buf_len: usize,
    /// `size_t buf_off`.
    buf_off: usize,
    /// `size_t buf_len_save`.
    buf_len_save: usize,
    /// `size_t buf_off_save`.
    buf_off_save: usize,
    /// `int cont` — `<= 0` when finished.
    cont: c_int,
    /// `int finished`.
    finished: c_int,
    /// `EVP_MD_CTX *md`.
    md: *mut EvpMdCtx,
    /// `int blockout` — output block is ready.
    blockout: c_int,
    /// `int sigio` — must process signature.
    sigio: c_int,
    /// `unsigned char buf[IOBS]`.
    buf: [c_uchar; IOBS],
}

/// `methods_ok` — `crypto/evp/bio_ok.c:112-125`, field for field.
///
/// The type is `BIO_TYPE_CIPHER` and the name is `"reliable"`, not a type of its own — the same
/// `BIO_TYPE_CIPHER` `BIO_f_cipher` uses.
static METHODS_OK: BioMethod = BioMethod {
    type_: BIO_TYPE_CIPHER,
    name: c"reliable".as_ptr(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(ok_write),
    bread: Some(bread_conv),
    bread_old: Some(ok_read),
    bputs: None, // ok_puts does not exist
    bgets: None, // ok_gets does not exist
    ctrl: Some(ok_ctrl),
    create: Some(ok_new),
    destroy: Some(ok_free),
    callback_ctrl: Some(ok_callback_ctrl),
    sendmmsg: None,
    recvmmsg: None,
};

/// `const BIO_METHOD *BIO_f_reliable(void)` — `crypto/evp/bio_ok.c:127-130`.
///
/// The answer is the address of the one shared table above, so two calls answer the same pointer
/// and a caller can compare either against `BIO_method_type`/`BIO_method_name` observations.
#[no_mangle]
pub extern "C" fn BIO_f_reliable() -> *const BioMethod {
    &METHODS_OK
}

/// `bio.h`'s `BIO_should_retry(a)` — `#define BIO_should_retry(a) BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY)`.
///
/// # Safety
/// `b` must be NULL or a live BIO.
#[inline]
unsafe fn bio_should_retry(b: *mut Bio) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { BIO_test_flags(b, BIO_FLAGS_SHOULD_RETRY) }
}

/// `bio.h`'s `BIO_clear_retry_flags(b)` — `BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY)`.
///
/// # Safety
/// `b` must be NULL or a live BIO.
#[inline]
unsafe fn bio_clear_retry_flags(b: *mut Bio) {
    // SAFETY: the caller's contract.
    unsafe {
        BIO_clear_flags(
            b,
            BIO_FLAGS_READ | BIO_FLAGS_WRITE | BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY,
        )
    };
}

/// `bio.h`'s `BIO_next(b)` — `#define BIO_next(b) ((b)->next_bio)`.
///
/// # Safety
/// `b` must be a live BIO.
#[inline]
unsafe fn bio_next(b: *mut Bio) -> *mut Bio {
    // SAFETY: the caller's contract.
    unsafe { (*b).next_bio }
}

/// This crate's spelling of `BIO_get_data(b)` for a [`BioOkCtx`].
///
/// # Safety
/// `b` must be NULL or a live BIO whose data slot holds a [`BioOkCtx`].
#[inline]
unsafe fn ok_ctx(b: *mut Bio) -> *mut BioOkCtx {
    // SAFETY: the caller's contract.
    unsafe { BIO_get_data(b).cast() }
}

/// `static int ok_new(BIO *bi)` — `crypto/evp/bio_ok.c:132-150`.
///
/// `cont` and `sigio` are **1**, and `BIO_set_init(bi, 0)` leaves the filter *uninitialised* until
/// `BIO_C_SET_MD` arms the digest — the discipline `BIO_f_md` uses. The context owns a fresh
/// `EVP_MD_CTX` from the start, and a failure to allocate it frees the context (`OPENSSL_free` is
/// `CRYPTO_free`) and answers 0 **without** publishing the data slot.
///
/// # Safety
/// `bi` must be the live BIO `BIO_new` is creating.
unsafe extern "C" fn ok_new(bi: *mut Bio) -> c_int {
    // SAFETY: `OPENSSL_zalloc` is `CRYPTO_zalloc`; the block is this call's own.
    let ctx = CRYPTO_zalloc(core::mem::size_of::<BioOkCtx>(), FILE, 136).cast::<BioOkCtx>();
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is a fresh zeroed block this call owns.
    unsafe {
        (*ctx).cont = 1;
        (*ctx).sigio = 1;
        (*ctx).md = EVP_MD_CTX_new();
        if (*ctx).md.is_null() {
            CRYPTO_free(ctx.cast(), FILE, 143);
            return 0;
        }
        BIO_set_init(bi, 0);
        BIO_set_data(bi, ctx.cast());
    }
    1
}

/// `static int ok_free(BIO *a)` — `crypto/evp/bio_ok.c:152-167`.
///
/// The authority does **not** null-check the data slot here, unlike `enc_free`: `ok_new` publishes
/// it only after `ctx->md` exists, so a BIO this method created always has a context. The context
/// is released with `OPENSSL_clear_free`, i.e. `CRYPTO_clear_free`.
///
/// # Safety
/// `a` must be NULL or a live BIO whose data slot holds a [`BioOkCtx`], or the BIO `BIO_free` is
/// destroying.
unsafe extern "C" fn ok_free(a: *mut Bio) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: `a` is live per the contract.
    let ctx = unsafe { ok_ctx(a) };
    // SAFETY: `ctx` is this BIO's own context, and `ok_new` publishes the data slot only once
    // `ctx->md` is non-NULL, so both the digest context and the block are this call's to release.
    unsafe {
        EVP_MD_CTX_free((*ctx).md);
        CRYPTO_clear_free(ctx.cast(), core::mem::size_of::<BioOkCtx>(), FILE, 162);
        BIO_set_data(a, ptr::null_mut());
        BIO_set_init(a, 0);
    }
    1
}

/// `static int ok_read(BIO *b, char *out, int outl)` — `crypto/evp/bio_ok.c:169-252`.
///
/// The read path drains the clean block it holds, then refills from the downstream BIO one
/// `IOBS - buf_len` chunk at a time and runs `sig_in` and then `block_in` over what arrived. A
/// failed `sig_in`/`block_in` answers **0** after clearing the retry flags; a downstream read that
/// answers `<= 0` ends the loop with whatever was already handed out. The retry flags are cleared
/// and the next BIO's are copied on **both** the loop's exits — the `break` path and the normal
/// end.
///
/// # Safety
/// `b` must be a live reliable filter whose next BIO is live and whose context has a digest armed;
/// `out` writable for `outl` bytes or NULL.
unsafe extern "C" fn ok_read(b: *mut Bio, out: *mut c_char, outl: c_int) -> c_int {
    let mut ret: c_int = 0;

    if out.is_null() {
        return 0;
    }
    // SAFETY: `b` is live per the contract.
    let ctx = unsafe { ok_ctx(b) };
    // SAFETY: as above.
    let next = unsafe { bio_next(b) };
    // SAFETY: `b` is live per the contract.
    if ctx.is_null() || next.is_null() || unsafe { BIO_get_init(b) } == 0 {
        return 0;
    }

    let mut out = out;
    let mut outl = outl;
    while outl > 0 {
        /* copy clean bytes to output buffer */
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).blockout } != 0 {
            // SAFETY: `ctx` is live.
            let mut i = (unsafe { (*ctx).buf_len } - unsafe { (*ctx).buf_off }) as c_int;
            if i > outl {
                i = outl;
            }
            // SAFETY: `ctx` owns `buf`; `buf_off .. buf_off + i` is in bounds and `out` is
            // writable for `outl >= i` bytes.
            unsafe {
                ptr::copy_nonoverlapping(
                    (*ctx).buf.as_ptr().add((*ctx).buf_off),
                    out.cast::<c_uchar>(),
                    i as usize,
                );
                ret += i;
                out = out.add(i as usize);
                (*ctx).buf_off += i as usize;
            }
            outl -= i;

            /* all clean bytes are out */
            // SAFETY: `ctx` is live.
            if unsafe { (*ctx).buf_len } == unsafe { (*ctx).buf_off } {
                // SAFETY: `ctx` is live; the `buf_off_save`/`buf_len_save` pair was set by
                // `block_in` when it accepted a block, so both offsets are inside `buf`.
                unsafe {
                    (*ctx).buf_off = 0;
                    if (*ctx).buf_len_save > (*ctx).buf_off_save {
                        (*ctx).buf_len = (*ctx).buf_len_save - (*ctx).buf_off_save;
                        ptr::copy(
                            (*ctx).buf.as_ptr().add((*ctx).buf_off_save),
                            (*ctx).buf.as_mut_ptr(),
                            (*ctx).buf_len,
                        );
                    } else {
                        (*ctx).buf_len = 0;
                    }
                    (*ctx).blockout = 0;
                }
            }
        }

        /* output buffer full -- cancel */
        if outl == 0 {
            break;
        }

        /* no clean bytes in buffer -- fill it */
        // SAFETY: `ctx` is live.
        let n = (IOBS - unsafe { (*ctx).buf_len }) as c_int;
        // SAFETY: `ctx` owns `buf` and `n` is `IOBS - buf_len`, so the destination is in bounds;
        // `next` is live.
        let i = unsafe { BIO_read(next, (*ctx).buf.as_mut_ptr().add((*ctx).buf_len).cast(), n) };
        if i <= 0 {
            break; /* nothing new */
        }
        // SAFETY: `ctx` is live and `i > 0` bytes were just read into `buf`.
        unsafe { (*ctx).buf_len += i as usize };

        /* no signature yet -- check if we got one */
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).sigio } == 1 {
            // SAFETY: `b` is live.
            if unsafe { sig_in(b) } == 0 {
                // SAFETY: `b` is live.
                unsafe { bio_clear_retry_flags(b) };
                return 0;
            }
        }

        /* signature ok -- check if we got block */
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).sigio } == 0 {
            // SAFETY: `b` is live.
            if unsafe { block_in(b) } == 0 {
                // SAFETY: `b` is live.
                unsafe { bio_clear_retry_flags(b) };
                return 0;
            }
        }

        /* invalid block -- cancel */
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).cont } <= 0 {
            break;
        }
    }

    // SAFETY: `b` is live.
    unsafe {
        bio_clear_retry_flags(b);
        BIO_copy_next_retry(b);
    }
    ret
}

/// `static int ok_write(BIO *b, const char *in, int inl)` — `crypto/evp/bio_ok.c:254-316`.
///
/// `ret` is the caller's `inl` — bytes **accepted** — and the record header is emitted first, by
/// `sig_out`, if this is the stream's opening write. The `do`/`while` drains any ready block before
/// it accepts more, refills the data half up to `OK_BLOCK_SIZE + OK_BLOCK_BLOCK`, and calls
/// `block_out` when it is full. A downstream write that answers `<= 0` returns that code and, when
/// the BIO is not retriable, marks the stream finished (`ctx->cont = 0`).
///
/// # Safety
/// `b` must be a live reliable filter whose next BIO is live and whose context has a digest armed;
/// `in` readable for `inl` bytes or NULL.
unsafe extern "C" fn ok_write(b: *mut Bio, in_: *const c_char, inl: c_int) -> c_int {
    if inl <= 0 {
        return inl;
    }
    // SAFETY: `b` is live per the contract.
    let ctx = unsafe { ok_ctx(b) };
    // SAFETY: as above.
    let next = unsafe { bio_next(b) };
    let ret = inl;

    // SAFETY: `b` is live per the contract.
    if ctx.is_null() || next.is_null() || unsafe { BIO_get_init(b) } == 0 {
        return 0;
    }

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).sigio } != 0 && unsafe { sig_out(b) } == 0 {
        return 0;
    }

    let mut in_ = in_;
    let mut inl = inl;
    loop {
        // SAFETY: `b` is live.
        unsafe { bio_clear_retry_flags(b) };
        // SAFETY: `ctx` is live.
        let mut n = (unsafe { (*ctx).buf_len } - unsafe { (*ctx).buf_off }) as c_int;
        // SAFETY: `ctx` is live. The two reads are through the pointer, which the lint cannot see
        // changing, and `n` is decremented below.
        while unsafe { (*ctx).blockout } != 0 && n > 0 {
            // SAFETY: `ctx` owns `buf` and `n <= buf_len - buf_off`, so the source is in bounds;
            // `next` is live.
            let i = unsafe { BIO_write(next, (*ctx).buf.as_ptr().add((*ctx).buf_off).cast(), n) };
            if i <= 0 {
                // SAFETY: `b` is live.
                unsafe { BIO_copy_next_retry(b) };
                // SAFETY: `b` is live.
                if unsafe { bio_should_retry(b) } == 0 {
                    // SAFETY: `ctx` is live.
                    unsafe { (*ctx).cont = 0 };
                }
                return i;
            }
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).buf_off += i as usize };
            n -= i;
        }

        /* at this point all pending data has been written */
        // SAFETY: `ctx` is live.
        unsafe {
            (*ctx).blockout = 0;
            if (*ctx).buf_len == (*ctx).buf_off {
                (*ctx).buf_len = OK_BLOCK_BLOCK;
                (*ctx).buf_off = 0;
            }
        }

        if in_.is_null() || inl <= 0 {
            return 0;
        }

        // SAFETY: `ctx` is live.
        let n = if inl as usize + unsafe { (*ctx).buf_len } > OK_BLOCK_SIZE + OK_BLOCK_BLOCK {
            // SAFETY: `ctx` is live.
            (OK_BLOCK_SIZE + OK_BLOCK_BLOCK - unsafe { (*ctx).buf_len }) as c_int
        } else {
            inl
        };
        // SAFETY: `ctx` owns `buf` and `buf_len + n <= OK_BLOCK_SIZE + OK_BLOCK_BLOCK <= IOBS`;
        // `in_` holds `inl >= n` readable bytes.
        unsafe {
            ptr::copy_nonoverlapping(
                in_.cast::<c_uchar>(),
                (*ctx).buf.as_mut_ptr().add((*ctx).buf_len),
                n as usize,
            );
            (*ctx).buf_len += n as usize;
        }
        inl -= n;
        // SAFETY: `n <= inl` before the subtraction, so the advance stays inside the caller's
        // buffer.
        in_ = unsafe { in_.add(n as usize) };

        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).buf_len } >= OK_BLOCK_SIZE + OK_BLOCK_BLOCK {
            // SAFETY: `b` is live.
            if unsafe { block_out(b) } == 0 {
                // SAFETY: `b` is live.
                unsafe { bio_clear_retry_flags(b) };
                return 0;
            }
        }

        /* the authority's `do { ... } while (inl > 0)` */
        if inl <= 0 {
            break;
        }
    }

    // SAFETY: `b` is live.
    unsafe {
        bio_clear_retry_flags(b);
        BIO_copy_next_retry(b);
    }
    ret
}

/// `static long ok_ctrl(BIO *b, int cmd, long num, void *ptr)` — `crypto/evp/bio_ok.c:318-402`.
///
/// The authority dereferences the context without a null test here, and so does this
/// transcription: every command below is reached only on a BIO `ok_new` built.
///
/// `BIO_CTRL_FLUSH` writes the pending block with `block_out` and then loops on
/// `ok_write(b, NULL, 0)` while `blockout` is set. `ok_write` answers 0 immediately for
/// `inl <= 0`, so that loop has no progress arm and the only exit in the authority is a negative
/// answer — the transcription keeps the loop and its single exit exactly. After the loop the
/// stream is marked `finished`, `buf_off`/`buf_len` are zeroed, `cont` takes the loop's `ret`, and
/// the underlying BIO is flushed.
///
/// # Safety
/// `b` must be a live reliable filter whose next BIO is live; `ptr` as the command requires.
unsafe extern "C" fn ok_ctrl(b: *mut Bio, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long {
    let mut ret: c_long = 1;

    // SAFETY: `b` is live per the contract.
    let ctx = unsafe { ok_ctx(b) };
    // SAFETY: as above.
    let next = unsafe { bio_next(b) };

    match cmd {
        BIO_CTRL_RESET => {
            // SAFETY: `ctx` is live.
            unsafe {
                (*ctx).buf_len = 0;
                (*ctx).buf_off = 0;
                (*ctx).buf_len_save = 0;
                (*ctx).buf_off_save = 0;
                (*ctx).cont = 1;
                (*ctx).finished = 0;
                (*ctx).blockout = 0;
                (*ctx).sigio = 1;
            }
            // SAFETY: `next` is live.
            ret = unsafe { BIO_ctrl(next, cmd, num, ptr) };
        }
        BIO_CTRL_EOF => {
            /* More to read */
            // SAFETY: `ctx` is live.
            ret = if unsafe { (*ctx).cont } <= 0 {
                1
            } else {
                // SAFETY: `next` is live.
                unsafe { BIO_ctrl(next, cmd, num, ptr) }
            };
        }
        BIO_CTRL_PENDING | BIO_CTRL_WPENDING => {
            /* More to read in buffer */
            // SAFETY: `ctx` is live.
            let pending = if unsafe { (*ctx).blockout } != 0 {
                // SAFETY: `ctx` is live.
                (unsafe { (*ctx).buf_len } - unsafe { (*ctx).buf_off }) as c_long
            } else {
                0
            };
            ret = pending;
            if ret <= 0 {
                // SAFETY: `next` is live.
                ret = unsafe { BIO_ctrl(next, cmd, num, ptr) };
            }
        }
        BIO_CTRL_FLUSH => {
            /* do a final write */
            // SAFETY: `ctx` is live.
            if unsafe { (*ctx).blockout } == 0 {
                // SAFETY: `b` is live.
                if unsafe { block_out(b) } == 0 {
                    return 0;
                }
            }

            loop {
                // SAFETY: `ctx` is live.
                if unsafe { (*ctx).blockout } == 0 {
                    break;
                }
                // SAFETY: `b` is live. For `inl == 0` `ok_write` answers 0 without touching
                // `blockout`, which is the authority's own loop condition.
                let i = unsafe { ok_write(b, ptr::null(), 0) };
                if i < 0 {
                    ret = c_long::from(i);
                    break;
                }
            }

            // SAFETY: `ctx` is live.
            unsafe {
                (*ctx).finished = 1;
                (*ctx).buf_off = 0;
                (*ctx).buf_len = 0;
                (*ctx).cont = ret as c_int;
            }

            /* Finally flush the underlying BIO */
            // SAFETY: `next` and `b` are live.
            unsafe {
                ret = BIO_ctrl(next, cmd, num, ptr);
                BIO_copy_next_retry(b);
            }
        }
        BIO_C_DO_STATE_MACHINE => {
            // SAFETY: `b` and `next` are live.
            unsafe {
                bio_clear_retry_flags(b);
                ret = BIO_ctrl(next, cmd, num, ptr);
                BIO_copy_next_retry(b);
            }
        }
        BIO_CTRL_INFO => {
            // SAFETY: `ctx` is live.
            ret = c_long::from(unsafe { (*ctx).cont });
        }
        BIO_C_SET_MD => {
            // SAFETY: `ctx->md` is live and `ptr` is the caller's `EVP_MD *`.
            let ok = unsafe { EVP_DigestInit_ex((*ctx).md, ptr.cast::<EvpMd>(), ptr::null_mut()) };
            if ok == 0 {
                return 0;
            }
            // SAFETY: `b` is live.
            unsafe { BIO_set_init(b, 1) };
        }
        BIO_C_GET_MD => {
            // SAFETY: `b` is live.
            if unsafe { BIO_get_init(b) } != 0 {
                // SAFETY: `ctx` is live and `ptr` is the caller's `const EVP_MD **`.
                unsafe {
                    *ptr.cast::<*const EvpMd>() = EVP_MD_CTX_get0_md((*ctx).md);
                }
            } else {
                ret = 0;
            }
        }
        _ => {
            // SAFETY: `next` is live.
            ret = unsafe { BIO_ctrl(next, cmd, num, ptr) };
        }
    }
    ret
}

/// `static long ok_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp)` — `crypto/evp/bio_ok.c:404-414`.
///
/// # Safety
/// `b` must be a live reliable filter.
unsafe extern "C" fn ok_callback_ctrl(b: *mut Bio, cmd: c_int, fp: Option<BioInfoCb>) -> c_long {
    // SAFETY: `b` is live per the contract.
    let next = unsafe { bio_next(b) };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `next` is live.
    unsafe { BIO_callback_ctrl(next, cmd, fp) }
}

/// `static void longswap(void *_ptr, size_t len)` — `crypto/evp/bio_ok.c:416-429`.
///
/// `DECLARE_IS_ENDIAN` selects the loop on `IS_LITTLE_ENDIAN` at compile time; on a big-endian
/// host the function is the identity, which is the file's documented reason the header's byte
/// order is "machine-dependent". The selection is `cfg!(target_endian = "little")` here, so the
/// byte string a little-endian caller sees is the swapped one.
///
/// # Safety
/// `ptr` must be writable for `len` bytes, and on the swapping arm `len` must be a multiple of
/// four — which every caller satisfies, since `len` is always a digest length.
unsafe fn longswap(ptr: *mut c_void, len: usize) {
    if cfg!(target_endian = "little") {
        let p = ptr.cast::<c_uchar>();
        let mut i = 0;
        while i < len {
            // SAFETY: the caller's contract; on this arm `i + 3 < len`, so all four bytes are
            // writable.
            unsafe {
                let c = *p.add(i);
                *p.add(i) = *p.add(i + 3);
                *p.add(i + 3) = c;
                let c = *p.add(i + 1);
                *p.add(i + 1) = *p.add(i + 2);
                *p.add(i + 2) = c;
            }
            i += 4;
        }
    }
}

/// `static int sig_out(BIO *b)` — `crypto/evp/bio_ok.c:431-473`.
///
/// The stream-opening write. The digest is re-initialised, its **state block** is overwritten with
/// `md_size` random bytes and those same bytes are appended to the record (the per-stream salt the
/// format's header carries), the well-known text is folded in, and the resulting digest is
/// appended too. `ctx->buf_len + 2 * md_size > OK_BLOCK_SIZE` is the one early answer that is
/// **1** and not an error: there is no room in this record, so the caller should come back later.
///
/// This is the unit's only reach into the random layer, and the authority's own comment above the
/// call is kept in spirit: there is no guarantee the fill makes any sense, particularly now
/// `EVP_MD_CTX` has been restructured — it overwrites the method's private state directly.
///
/// # Safety
/// `b` must be a live reliable filter whose context has a digest armed and whose next BIO is live.
unsafe extern "C" fn sig_out(b: *mut Bio) -> c_int {
    // SAFETY: `b` is live per the contract.
    let ctx = unsafe { ok_ctx(b) };
    // SAFETY: `ctx` is live.
    let md = unsafe { (*ctx).md };
    // SAFETY: `md` is live; a NULL digest method is accepted and answers NULL.
    let digest = unsafe { EVP_MD_CTX_get0_md(md) };
    // SAFETY: `digest` is NULL or live; a NULL method answers -1, which the test below refuses.
    let md_size = unsafe { EVP_MD_get_size(digest) };
    // SAFETY: `md` is live.
    let md_data = unsafe { EVP_MD_CTX_get0_md_data(md) };

    'berr: {
        if md_size <= 0 {
            break 'berr;
        }
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).buf_len } + 2 * md_size as usize > OK_BLOCK_SIZE {
            return 1;
        }

        // SAFETY: `md` and `digest` are live, and the third argument is the authority's NULL.
        if unsafe { EVP_DigestInit_ex(md, digest, ptr::null_mut()) } == 0 {
            break 'berr;
        }
        /*
         * FIXME: there's absolutely no guarantee this makes any sense at all,
         * particularly now EVP_MD_CTX has been restructured.
         */
        // SAFETY: `md_data` points at the digest method's own `md_size`-byte state block, and
        // `RAND_bytes` writes `md_size` bytes into it.
        if unsafe { RAND_bytes(md_data.cast::<c_uchar>(), md_size) } <= 0 {
            break 'berr;
        }
        // SAFETY: `ctx` owns `buf`; the test above bounds `buf_len + 2 * md_size` by
        // `OK_BLOCK_SIZE`, and `md_data` holds `md_size` bytes. `longswap` may write `md_size`
        // bytes in place, which is the same in-bounds span.
        unsafe {
            ptr::copy_nonoverlapping(
                md_data.cast::<c_uchar>(),
                (*ctx).buf.as_mut_ptr().add((*ctx).buf_len),
                md_size as usize,
            );
            longswap(
                (*ctx).buf.as_mut_ptr().add((*ctx).buf_len).cast(),
                md_size as usize,
            );
            (*ctx).buf_len += md_size as usize;
        }

        // SAFETY: `md` is live and `WELLKNOWN` is a static string of `WELLKNOWN.len()` bytes.
        if unsafe { EVP_DigestUpdate(md, WELLKNOWN.as_ptr().cast::<c_void>(), WELLKNOWN.len()) }
            == 0
        {
            break 'berr;
        }
        // SAFETY: `md` is live and `ctx->buf` has room for `md_size` more bytes at `buf_len`.
        if unsafe {
            EVP_DigestFinal_ex(
                md,
                (*ctx).buf.as_mut_ptr().add((*ctx).buf_len),
                ptr::null_mut(),
            )
        } == 0
        {
            break 'berr;
        }
        // SAFETY: `ctx` is live.
        unsafe {
            (*ctx).buf_len += md_size as usize;
            (*ctx).blockout = 1;
            (*ctx).sigio = 0;
        }
        return 1;
    }
    /* berr: */
    // SAFETY: `b` is live.
    unsafe { bio_clear_retry_flags(b) };
    0
}

/// `static int sig_in(BIO *b)` — `crypto/evp/bio_ok.c:475-523`.
///
/// The reader's counterpart: the salt half of the header is copied **into** the digest method's
/// state block (un-swapped), the well-known text is folded in, and the answer is compared against
/// the digest half of the header. Fewer than `2 * md_size` buffered bytes answers **1** and waits
/// for more, without clearing the retry flags; a match clears `sigio` and slides the block start
/// down, and a mismatch sets `ctx->cont = 0`.
///
/// # Safety
/// `b` must be a live reliable filter whose context has a digest armed and whose next BIO is live.
unsafe extern "C" fn sig_in(b: *mut Bio) -> c_int {
    // SAFETY: `b` is live per the contract.
    let ctx = unsafe { ok_ctx(b) };
    let mut tmp = [0u8; EVP_MAX_MD_SIZE];

    'berr: {
        // SAFETY: `ctx` is live.
        let md = unsafe { (*ctx).md };
        if md.is_null() {
            break 'berr;
        }
        // SAFETY: `md` is live.
        let digest = unsafe { EVP_MD_CTX_get0_md(md) };
        // SAFETY: `digest` is NULL or live.
        let md_size = unsafe { EVP_MD_get_size(digest) };
        if md_size <= 0 {
            break 'berr;
        }
        // SAFETY: `md` is live.
        let md_data = unsafe { EVP_MD_CTX_get0_md_data(md) };

        // SAFETY: `ctx` is live.
        if ((unsafe { (*ctx).buf_len } - unsafe { (*ctx).buf_off }) as c_int) < 2 * md_size {
            return 1;
        }

        // SAFETY: `md` and `digest` are live, and the third argument is the authority's NULL.
        if unsafe { EVP_DigestInit_ex(md, digest, ptr::null_mut()) } == 0 {
            break 'berr;
        }
        // SAFETY: `ctx` owns `buf`; the test above requires `2 * md_size` readable bytes from
        // `buf_off`, and `md_data` is `md_size` writable bytes.
        unsafe {
            ptr::copy_nonoverlapping(
                (*ctx).buf.as_ptr().add((*ctx).buf_off),
                md_data.cast::<c_uchar>(),
                md_size as usize,
            );
            longswap(md_data, md_size as usize);
            (*ctx).buf_off += md_size as usize;
        }

        // SAFETY: `md` is live and `WELLKNOWN` is a static string of `WELLKNOWN.len()` bytes.
        if unsafe { EVP_DigestUpdate(md, WELLKNOWN.as_ptr().cast::<c_void>(), WELLKNOWN.len()) }
            == 0
        {
            break 'berr;
        }
        // SAFETY: `md` is live and `tmp` is `EVP_MAX_MD_SIZE` bytes, the digest maximum.
        if unsafe { EVP_DigestFinal_ex(md, tmp.as_mut_ptr(), ptr::null_mut()) } == 0 {
            break 'berr;
        }
        // SAFETY: `ctx` owns `buf`; the test above placed `md_size` readable bytes at `buf_off`,
        // and `tmp` holds `md_size` bytes.
        let ret = c_int::from(unsafe {
            sys::memcmp(
                (*ctx).buf.as_ptr().add((*ctx).buf_off).cast::<c_void>(),
                tmp.as_ptr().cast::<c_void>(),
                md_size as usize,
            ) == 0
        });
        // SAFETY: `ctx` is live.
        unsafe {
            (*ctx).buf_off += md_size as usize;
            if ret == 1 {
                (*ctx).sigio = 0;
                if (*ctx).buf_len != (*ctx).buf_off {
                    ptr::copy(
                        (*ctx).buf.as_ptr().add((*ctx).buf_off),
                        (*ctx).buf.as_mut_ptr(),
                        (*ctx).buf_len - (*ctx).buf_off,
                    );
                }
                (*ctx).buf_len -= (*ctx).buf_off;
                (*ctx).buf_off = 0;
            } else {
                (*ctx).cont = 0;
            }
        }
        return 1;
    }
    /* berr: */
    // SAFETY: `b` is live.
    unsafe { bio_clear_retry_flags(b) };
    0
}

/// `static int block_out(BIO *b)` — `crypto/evp/bio_ok.c:525-556`.
///
/// The data half's four-byte big-endian length is written first, the data half is folded into the
/// digest, and the digest is appended after it. `md_size <= 0` is the only refusal that reaches
/// `berr`.
///
/// # Safety
/// `b` must be a live reliable filter whose context is mid-record (its data half holds
/// `OK_BLOCK_BLOCK` or more bytes) and whose next BIO is live.
unsafe extern "C" fn block_out(b: *mut Bio) -> c_int {
    // SAFETY: `b` is live per the contract.
    let ctx = unsafe { ok_ctx(b) };
    // SAFETY: `ctx` is live.
    let md = unsafe { (*ctx).md };
    // SAFETY: `md` is live; a NULL digest method is accepted and answers NULL.
    let digest = unsafe { EVP_MD_CTX_get0_md(md) };
    // SAFETY: `digest` is NULL or live; a NULL method answers -1, which the test below refuses.
    let md_size = unsafe { EVP_MD_get_size(digest) };

    'berr: {
        if md_size <= 0 {
            break 'berr;
        }

        // SAFETY: `ctx` is live and `buf_len >= OK_BLOCK_BLOCK` whenever this runs, so the
        // subtraction is the data half's own length.
        let tl = unsafe { (*ctx).buf_len } - OK_BLOCK_BLOCK;
        // SAFETY: `ctx` owns `buf`; the first four bytes are the length field.
        unsafe {
            (*ctx).buf[0] = (tl >> 24) as c_uchar;
            (*ctx).buf[1] = (tl >> 16) as c_uchar;
            (*ctx).buf[2] = (tl >> 8) as c_uchar;
            (*ctx).buf[3] = tl as c_uchar;
        }

        // SAFETY: `md` is live and `ctx->buf[OK_BLOCK_BLOCK..]` holds `tl` bytes.
        if unsafe {
            EVP_DigestUpdate(
                md,
                (*ctx).buf.as_ptr().add(OK_BLOCK_BLOCK).cast::<c_void>(),
                tl,
            )
        } == 0
        {
            break 'berr;
        }
        // SAFETY: `md` is live and `ctx->buf` has room for `md_size` bytes at `buf_len`.
        if unsafe {
            EVP_DigestFinal_ex(
                md,
                (*ctx).buf.as_mut_ptr().add((*ctx).buf_len),
                ptr::null_mut(),
            )
        } == 0
        {
            break 'berr;
        }
        // SAFETY: `ctx` is live.
        unsafe {
            (*ctx).buf_len += md_size as usize;
            (*ctx).blockout = 1;
        }
        return 1;
    }
    /* berr: */
    // SAFETY: `b` is live.
    unsafe { bio_clear_retry_flags(b) };
    0
}

/// `static int block_in(BIO *b)` — `crypto/evp/bio_ok.c:558-606`.
///
/// Two refusals with the same `berr`: a declared length above `OK_BLOCK_SIZE`, and a length for
/// which `tl + OK_BLOCK_BLOCK + md_size` would wrap `SIZE_MAX`. A record too short to hold
/// `tl + OK_BLOCK_BLOCK + md_size` answers **1** and waits. On a digest match the data half
/// becomes the clean block and the offsets into any successor bytes are saved in
/// `buf_off_save`/`buf_len_save`; on a mismatch `ctx->cont = 0`.
///
/// The authority's `assert(sizeof(tl) >= OK_BLOCK_BLOCK)` is `NDEBUG`'s identity — a `size_t`
/// always holds four bytes — so it is recorded here and not transcribed as a test.
///
/// # Safety
/// `b` must be a live reliable filter whose context has a digest armed and whose next BIO is live.
unsafe extern "C" fn block_in(b: *mut Bio) -> c_int {
    // SAFETY: `b` is live per the contract.
    let ctx = unsafe { ok_ctx(b) };
    // SAFETY: `ctx` is live.
    let md = unsafe { (*ctx).md };
    // SAFETY: `md` is live and `EVP_MD_CTX_get0_md` accepts a NULL digest method.
    let md_size = unsafe { EVP_MD_get_size(EVP_MD_CTX_get0_md(md)) };
    let mut tmp = [0u8; EVP_MAX_MD_SIZE];

    'berr: {
        if md_size <= 0 {
            break 'berr;
        }

        /* assert(sizeof(tl) >= OK_BLOCK_BLOCK); -- always true */
        // SAFETY: `ctx` owns `buf`; the first four bytes are the length field.
        let tl = unsafe {
            ((*ctx).buf[0] as usize) << 24
                | ((*ctx).buf[1] as usize) << 16
                | ((*ctx).buf[2] as usize) << 8
                | ((*ctx).buf[3] as usize)
        };

        if tl > OK_BLOCK_SIZE {
            break 'berr;
        }
        if tl > usize::MAX - OK_BLOCK_BLOCK - md_size as usize {
            break 'berr;
        }

        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).buf_len } < tl + OK_BLOCK_BLOCK + md_size as usize {
            return 1;
        }

        // SAFETY: `md` is live and `ctx->buf[OK_BLOCK_BLOCK..]` holds `tl` bytes.
        if unsafe {
            EVP_DigestUpdate(
                md,
                (*ctx).buf.as_ptr().add(OK_BLOCK_BLOCK).cast::<c_void>(),
                tl,
            )
        } == 0
        {
            break 'berr;
        }
        // SAFETY: `md` is live and `tmp` is `EVP_MAX_MD_SIZE` bytes, the digest maximum.
        if unsafe { EVP_DigestFinal_ex(md, tmp.as_mut_ptr(), ptr::null_mut()) } == 0 {
            break 'berr;
        }
        // SAFETY: `ctx` owns `buf`; the test above placed `tl + OK_BLOCK_BLOCK + md_size` bytes in
        // bounds, and `tmp` holds `md_size`.
        let eq = unsafe {
            sys::memcmp(
                (*ctx)
                    .buf
                    .as_ptr()
                    .add(tl + OK_BLOCK_BLOCK)
                    .cast::<c_void>(),
                tmp.as_ptr().cast::<c_void>(),
                md_size as usize,
            ) == 0
        };
        if eq {
            /* there might be parts from next block lurking around ! */
            // SAFETY: `ctx` is live; the saved offsets point inside `buf` because of the length
            // test above.
            unsafe {
                (*ctx).buf_off_save = tl + OK_BLOCK_BLOCK + md_size as usize;
                (*ctx).buf_len_save = (*ctx).buf_len;
                (*ctx).buf_off = OK_BLOCK_BLOCK;
                (*ctx).buf_len = tl + OK_BLOCK_BLOCK;
                (*ctx).blockout = 1;
            }
        } else {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).cont = 0 };
        }
        return 1;
    }
    /* berr: */
    // SAFETY: `b` is live.
    unsafe { bio_clear_retry_flags(b) };
    0
}
