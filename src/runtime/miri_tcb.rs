//! Phase 18 — the **Miri-admitted TCB suite**.
//!
//! This module is compiled only under `cargo +nightly miri test` (`cfg(miri)` and
//! `cfg(test)`); `cargo test` does not build it, so it changes no ordinary test
//! count and no product path. Its purpose is to make the crate's trusted computing
//! base executable under Miri's pointer-provenance model, so the specific classes
//! Miri catches — provenance loss, use-after-free, out-of-bounds, aliasing — are
//! run over the code that owns them.
//!
//! ## Admitted vs unsupported, and why the split is explicit
//!
//! Miri cannot execute a foreign (C) function. Two consequences shape this suite,
//! and neither is a suppression of a real result:
//!
//! * **libc FFI is unsupported.** The product's default allocator *is* libc
//!   `malloc`/`realloc`/`free` (`src/runtime/mem.rs`), so any test that reaches the
//!   default branch stops at Miri's "foreign function" refusal. The suite installs
//!   a **Rust-backed allocator shim** through the public
//!   `CRYPTO_set_mem_functions` before its first allocation, so every `CRYPTO_*`
//!   call routes through `std::alloc` — which Miri implements — instead of libc.
//!   The default branch itself is therefore *excluded* (classified unsupported),
//!   not silenced: the ordinary `cargo test` suite still exercises it.
//! * **DSOs, ucontext and CPU intrinsics are unsupported.** `src/dso`, the
//!   `ucontext` fibre shims in `src/async/arch/async_posix.c`, `getrandom` and the
//!   `rdtsc` paths call foreign functions or inline `asm!`; tests that reach them
//!   are excluded by name in `forensics/miri-tcb-suite.json` with the reason.
//!
//! ## What this suite exercises
//!
//! The allocator callback storage and the `CRYPTO_*` ownership surface; the X.509
//! refcount/lifetime state machine (the exact `item_embed_new <- CRYPTO_zalloc`
//! path the strict-provenance blocker stopped at); the `OPENSSL_STACK` and
//! `OPENSSL_LHASH` containers; the `BUF_MEM` buffer gateway; and the object
//! registry. The `.c`/FFI boundaries and the ASN.1 template interpreter's
//! function-pointer fields are exercised *through* these, which is what makes the
//! pointer->function-pointer recovery in `mem.rs`/`utx` observable rather than
//! asserted.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core::ffi::{c_char, c_int, c_void};
use core::mem::size_of;
use core::ptr;
use std::alloc::{alloc, dealloc, Layout};
use std::sync::Once;

use crate::runtime::mem::{
    CRYPTO_calloc, CRYPTO_clear_free, CRYPTO_clear_realloc, CRYPTO_free, CRYPTO_get_mem_functions,
    CRYPTO_malloc, CRYPTO_memdup, CRYPTO_realloc, CRYPTO_set_mem_functions, CRYPTO_strdup,
    CRYPTO_strndup, CRYPTO_zalloc,
};

/// The shim's alignment: at least `malloc`'s on this platform, so a caller that
/// assumes a `malloc`-aligned block is satisfied.
const SHIM_ALIGN: usize = 16;
/// Each shim block carries its request size in this many leading bytes, because the
/// authority's `CRYPTO_free_fn` takes no size and `std::alloc::dealloc` needs one.
const SHIM_HEADER: usize = size_of::<usize>();

/// Installs the Rust-backed shim exactly once. All admitted tests call it first;
/// because the Miri run is filtered to `miri_tcb`, no default-branch allocation has
/// happened yet and `ALLOW_CUSTOMIZE` is still set.
static INSTALL: Once = Once::new();

/// # Safety
/// Matches `CRYPTO_malloc_fn`: answers NULL or a block of `n` bytes.
unsafe extern "C" fn shim_malloc(n: usize, _file: *const c_char, _line: c_int) -> *mut c_void {
    let total = match n.checked_add(SHIM_HEADER) {
        Some(t) if t > 0 => t,
        _ => return ptr::null_mut(),
    };
    let layout = match Layout::from_size_align(total, SHIM_ALIGN) {
        Ok(l) => l,
        Err(_) => return ptr::null_mut(),
    };
    // SAFETY: `layout` has non-zero size (verified above).
    let base = unsafe { alloc(layout) };
    if base.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `base` is fresh and at least `SHIM_HEADER` bytes.
    unsafe { (base as *mut usize).write(n) };
    // SAFETY: `base` is valid for `total` bytes and `SHIM_HEADER < total`.
    unsafe { base.add(SHIM_HEADER).cast::<c_void>() }
}

/// Recover the request size and the underlying allocation from a shim pointer.
///
/// # Safety
/// `p` must be a non-null pointer returned by [`shim_malloc`].
unsafe fn shim_header(p: *mut c_void) -> (usize, *mut u8) {
    // SAFETY: `p` came from `shim_malloc`, so `p - SHIM_HEADER` is its base.
    let base = unsafe { (p as *mut u8).sub(SHIM_HEADER) };
    // SAFETY: the header was written by `shim_malloc`.
    let n = unsafe { (base as *mut usize).read() };
    (n, base)
}

/// # Safety
/// Matches `CRYPTO_free_fn`: `p` is NULL or a block from [`shim_malloc`].
unsafe extern "C" fn shim_free(p: *mut c_void, _file: *const c_char, _line: c_int) {
    if p.is_null() {
        return;
    }
    // SAFETY: `p` is a live shim block.
    let (n, base) = unsafe { shim_header(p) };
    let total = n + SHIM_HEADER;
    // SAFETY: `total`/`SHIM_ALIGN` are the values `shim_malloc` used for this block.
    let layout = unsafe { Layout::from_size_align_unchecked(total, SHIM_ALIGN) };
    // SAFETY: `base` is the allocation `shim_malloc` returned, with that layout.
    unsafe { dealloc(base, layout) };
}

/// # Safety
/// Matches `CRYPTO_realloc_fn`.
unsafe extern "C" fn shim_realloc(
    p: *mut c_void,
    n: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    if p.is_null() {
        // SAFETY: the shim's allocator contract.
        return unsafe { shim_malloc(n, file, line) };
    }
    // SAFETY: `p` is a live shim block.
    let (old, _base) = unsafe { shim_header(p) };
    if n == 0 {
        // SAFETY: `p` is a live block this allocator owns.
        unsafe { shim_free(p, file, line) };
        return ptr::null_mut();
    }
    // SAFETY: the shim's allocator contract.
    let q = unsafe { shim_malloc(n, file, line) };
    if q.is_null() {
        return ptr::null_mut();
    }
    let copy = old.min(n);
    // SAFETY: both blocks are live for `copy` bytes and distinct.
    unsafe { ptr::copy_nonoverlapping(p.cast::<u8>(), q.cast::<u8>(), copy) };
    // SAFETY: `p` is live and owned by this allocator.
    unsafe { shim_free(p, file, line) };
    q
}

/// Install the shim, once, before the first `CRYPTO_*` allocation.
fn install() {
    INSTALL.call_once(|| {
        // SAFETY: the three shims satisfy the `CRYPTO_*_fn` contract and are
        // `'static`. This is the first `CRYPTO_*` call in the filtered process.
        let rc = unsafe {
            CRYPTO_set_mem_functions(Some(shim_malloc), Some(shim_realloc), Some(shim_free))
        };
        assert_eq!(
            rc, 1,
            "the Rust shim must install before any default allocation"
        );
    });
}

/// Frees one `CRYPTO_*` block, for use as an `OPENSSL_STACK` destructor.
///
/// # Safety
/// `p` is NULL or a block from this process's installed allocator.
unsafe extern "C" fn free_one(p: *mut c_void) {
    // SAFETY: `p` is NULL or live per the caller's contract.
    unsafe { CRYPTO_free(p, ptr::null(), 0) };
}

#[test]
fn miri_tcb_allocator_slot_reports_the_installed_shim() {
    install();
    let mut m = None;
    let mut r = None;
    let mut f = None;
    // SAFETY: the three outputs are locals writable for one pointer each.
    unsafe { CRYPTO_get_mem_functions(&mut m, &mut r, &mut f) };
    assert!(
        m.is_some() && r.is_some() && f.is_some(),
        "every slot reports a function"
    );
    // A zero-length request answers non-null only through an installed allocator; the
    // default branch answers NULL for zero. That distinguishes the slot's contents
    // from the libc default by behaviour, which is robust where comparing function
    // addresses across coercion sites is not (Miri does not make those stable).
    let zero = CRYPTO_malloc(0, ptr::null(), 0);
    assert!(
        !zero.is_null(),
        "the installed branch handles a zero-length request"
    );
    // SAFETY: `zero` came from the installed allocator.
    unsafe { CRYPTO_free(zero, ptr::null(), 0) };
    // Call the *recovered* malloc/free directly. This is the property the pointer
    // slot exists for: the reported function pointers are callable, because their
    // provenance survived the atomic store and the pointer->function-pointer
    // recovery. Under the old integer slot this is exactly where Miri stopped.
    let p = unsafe { m.unwrap()(16, ptr::null(), 0) };
    assert!(!p.is_null());
    // SAFETY: `p` came from the allocator `m` names; `f` is that allocator's free.
    unsafe { f.unwrap()(p, ptr::null(), 0) };
}

#[test]
fn miri_tcb_alloc_zalloc_calloc_own_zero_and_release() {
    install();
    let p = CRYPTO_malloc(64, ptr::null(), 0);
    assert!(!p.is_null());
    // SAFETY: 64 bytes were requested.
    unsafe { ptr::write_bytes(p.cast::<u8>(), 0xAB, 64) };
    // SAFETY: `p` is live for 64 bytes.
    assert_eq!(unsafe { p.cast::<u8>().read() }, 0xAB);
    // SAFETY: `p` came from this allocator.
    unsafe { CRYPTO_free(p, ptr::null(), 0) };

    let z = CRYPTO_zalloc(16, ptr::null(), 0);
    assert!(!z.is_null());
    for i in 0..16 {
        // SAFETY: `z` is live for 16 zeroed bytes.
        assert_eq!(unsafe { z.cast::<u8>().add(i).read() }, 0);
    }
    // SAFETY: `z` came from this allocator.
    unsafe { CRYPTO_free(z, ptr::null(), 0) };

    let c = CRYPTO_calloc(4, 8, ptr::null(), 0);
    assert!(!c.is_null());
    // SAFETY: `c` is live for 32 zeroed bytes.
    unsafe { assert_eq!(c.cast::<u8>().read(), 0) };
    // SAFETY: `c` came from this allocator.
    unsafe { CRYPTO_free(c, ptr::null(), 0) };
}

#[test]
fn miri_tcb_realloc_preserves_and_clear_realloc_shrinks_in_place() {
    install();
    let p = CRYPTO_malloc(32, ptr::null(), 0);
    assert!(!p.is_null());
    // SAFETY: 32 bytes were requested.
    unsafe { ptr::write_bytes(p.cast::<u8>(), 0x5A, 32) };
    // SAFETY: `p` is a live block of 32 bytes.
    let q = unsafe { CRYPTO_realloc(p, 128, ptr::null(), 0) };
    assert!(!q.is_null());
    // SAFETY: `q` is live for at least the leading byte.
    assert_eq!(
        unsafe { q.cast::<u8>().read() },
        0x5A,
        "realloc preserves the prefix"
    );
    // SAFETY: `q` is live for 128 bytes.
    let r = unsafe { CRYPTO_clear_realloc(q, 128, 16, ptr::null(), 0) };
    assert_eq!(q, r, "the shrink path must not relocate the block");
    // SAFETY: `r` is live for the kept prefix.
    assert_eq!(unsafe { r.cast::<u8>().read() }, 0x5A);
    // SAFETY: `r` is live for 16 bytes; the zero-length path releases it.
    let z = unsafe { CRYPTO_clear_realloc(r, 16, 0, ptr::null(), 0) };
    assert!(z.is_null());
}

#[test]
fn miri_tcb_strdup_strndup_and_memdup_own_copies() {
    install();
    // SAFETY: the string is NUL-terminated.
    let s = unsafe { CRYPTO_strdup(c"hello".as_ptr(), ptr::null(), 0) };
    assert!(!s.is_null());
    // SAFETY: `s` is a NUL-terminated copy.
    assert_eq!(unsafe { core::ffi::CStr::from_ptr(s) }.to_bytes(), b"hello");
    // SAFETY: `s` came from this allocator.
    unsafe { CRYPTO_free(s.cast(), ptr::null(), 0) };

    // SAFETY: the source is NUL-terminated; `max` bounds the copy.
    let sn = unsafe { CRYPTO_strndup(c"hello".as_ptr(), 3, ptr::null(), 0) };
    // SAFETY: `sn` is a NUL-terminated copy of at most 3 bytes.
    assert_eq!(unsafe { core::ffi::CStr::from_ptr(sn) }.to_bytes(), b"hel");
    // SAFETY: `sn` came from this allocator.
    unsafe { CRYPTO_free(sn.cast(), ptr::null(), 0) };

    let src = [1u8, 2, 3, 4];
    // SAFETY: `src` is readable for 4 bytes.
    let d = unsafe { CRYPTO_memdup(src.as_ptr().cast(), 4, ptr::null(), 0) };
    assert!(!d.is_null());
    // SAFETY: `d` is live for 4 bytes.
    assert_eq!(
        unsafe { core::slice::from_raw_parts(d.cast::<u8>(), 4) },
        &src
    );
    // SAFETY: `d` came from this allocator, which is live for 4 bytes.
    unsafe { CRYPTO_clear_free(d, 4, ptr::null(), 0) };
}

#[test]
fn miri_tcb_buffer_gateway_grows_and_releases() {
    install();
    let m = crate::runtime::buffer::BUF_MEM_new();
    assert!(!m.is_null());
    // SAFETY: `m` is a live BUF_MEM.
    assert_eq!(unsafe { crate::runtime::buffer::BUF_MEM_grow(m, 100) }, 100);
    // SAFETY: `m` is a live BUF_MEM.
    assert_eq!(
        unsafe { crate::runtime::buffer::BUF_MEM_grow_clean(m, 200) },
        200
    );
    // SAFETY: `m` is a live BUF_MEM this call owns.
    unsafe { crate::runtime::buffer::BUF_MEM_free(m) };
}

#[test]
fn miri_tcb_stack_lifetimes_and_pop_free() {
    install();
    let a = CRYPTO_malloc(8, ptr::null(), 0);
    let b = CRYPTO_malloc(8, ptr::null(), 0);
    assert!(!a.is_null() && !b.is_null());
    let sk = crate::runtime::stack::OPENSSL_sk_new_null();
    assert!(!sk.is_null());
    // SAFETY: `sk` is live; `a`/`b` are the caller's pointers.
    unsafe {
        assert!(crate::runtime::stack::OPENSSL_sk_push(sk, a) >= 1);
        assert!(crate::runtime::stack::OPENSSL_sk_push(sk, b) >= 2);
    }
    // SAFETY: `sk` is live.
    unsafe {
        assert_eq!(crate::runtime::stack::OPENSSL_sk_num(sk), 2);
        assert_eq!(crate::runtime::stack::OPENSSL_sk_value(sk, 0), a);
        // Releases the stack and, through the destructor, each element.
        crate::runtime::stack::OPENSSL_sk_pop_free(sk, Some(free_one));
    }
}

#[test]
fn miri_tcb_lhash_registry_insert_retrieve_delete() {
    install();
    // SAFETY: `p` is the caller's key; the identity hash is enough for a registry.
    unsafe extern "C" fn hash(p: *const c_void) -> core::ffi::c_ulong {
        p as core::ffi::c_ulong
    }
    // SAFETY: the two keys are compared by identity.
    unsafe extern "C" fn cmp(a: *const c_void, b: *const c_void) -> c_int {
        c_int::from(a != b)
    }
    let lh = crate::runtime::lhash::OPENSSL_LH_new(Some(hash), Some(cmp));
    assert!(!lh.is_null());
    let mut key_a: usize = 7;
    let mut key_b: usize = 9;
    let pa = (&mut key_a as *mut usize).cast::<c_void>();
    let pb = (&mut key_b as *mut usize).cast::<c_void>();
    // SAFETY: `lh` is live; `pa`/`pb` outlive the hash while it is used.
    unsafe {
        assert_eq!(
            crate::runtime::lhash::OPENSSL_LH_insert(lh, pa),
            ptr::null_mut()
        );
        assert_eq!(
            crate::runtime::lhash::OPENSSL_LH_insert(lh, pb),
            ptr::null_mut()
        );
        assert_eq!(crate::runtime::lhash::OPENSSL_LH_num_items(lh), 2);
        assert_eq!(crate::runtime::lhash::OPENSSL_LH_retrieve(lh, pa), pa);
        assert_eq!(crate::runtime::lhash::OPENSSL_LH_delete(lh, pb), pb);
        assert_eq!(
            crate::runtime::lhash::OPENSSL_LH_retrieve(lh, pb),
            ptr::null_mut()
        );
        crate::runtime::lhash::OPENSSL_LH_free(lh);
    }
}

#[test]
fn miri_tcb_object_registry_lookup_round_trips() {
    install();
    use crate::runtime::obj::{NID_rsaEncryption, OBJ_nid2obj, OBJ_obj2nid};
    let ob = OBJ_nid2obj(NID_rsaEncryption);
    assert!(!ob.is_null());
    // SAFETY: `ob` is a live object from the registry.
    let nid = unsafe { OBJ_obj2nid(ob) };
    assert_eq!(nid, NID_rsaEncryption);
}

#[test]
fn miri_tcb_x509_lifetime_and_refcount() {
    use crate::x509::x509_set::X509_up_ref;
    use crate::x509::x_x509::{X509_free, X509_new};
    install();
    let x = X509_new();
    assert!(!x.is_null());
    // SAFETY: `x` is a freshly built X509 owned by this frame.
    unsafe {
        assert_eq!((*x).references, 1, "a fresh X509 starts at reference 1");
        assert_eq!(
            X509_up_ref(x),
            1,
            "up_ref reports that the old count was >= 1"
        );
        assert_eq!((*x).references, 2);
        // The first free is a decrement, not a release.
        X509_free(x);
        assert_eq!(
            (*x).references,
            1,
            "the item layer decrements under ASN1_AFLG_REFCOUNT"
        );
        // The second free reaches zero and releases the value (embeds, names, ex_data).
        X509_free(x);
    }
}
