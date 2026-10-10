//! Phase 25.8 differential harness: the sparse array under a caller-installed allocator.
//!
//! This is test-only tooling, not product. `forensics/tools/ms_sparse_array_court.py` runs it
//! against the crate and the matching C probe (`courts/phase25/rt_sparse_array_probe.c`)
//! against the admitted authority, and compares the two transcripts: the insert / replace /
//! remove / depth-growth return values, the numeric boundary, the walk order, the
//! allocation-hook observations and the allocation-failure answer.
//!
//! The harness installs the crate's allocator seam (`CRYPTO_set_mem_functions`) with counting,
//! recording hooks and drives the `ossl_sa_*` internals exactly as the C probe drives the
//! authority's. Because installing the allocator is a **process-global** act that would perturb
//! the crate's own allocator tests if it ran in the ordinary suite, the test is a no-op unless
//! `SPARSE_ARRAY_PROBE=1` is set in the environment; the court runs it with that variable and an
//! exact filter, so it is the only test in its process.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use std::sync::Mutex;

use crate::runtime::mem::{CRYPTO_malloc, CRYPTO_set_mem_functions};
use crate::runtime::sparse_array::{
    ossl_sa_doall_arg, ossl_sa_free, ossl_sa_free_leaves, ossl_sa_get, ossl_sa_new, ossl_sa_num,
    ossl_sa_set, OsslUintMax,
};

extern "C" {
    fn malloc(n: usize) -> *mut c_void;
    fn realloc(p: *mut c_void, n: usize) -> *mut c_void;
    fn free(p: *mut c_void);
}

static MALLOCS: AtomicI64 = AtomicI64::new(0);
static FREES: AtomicI64 = AtomicI64::new(0);
static FAIL_NEXT: AtomicBool = AtomicBool::new(false);
static SIZES: Mutex<Vec<u64>> = Mutex::new(Vec::new());

unsafe extern "C" fn hook_malloc(n: usize, _file: *const c_char, _line: c_int) -> *mut c_void {
    if FAIL_NEXT.swap(false, Ordering::SeqCst) {
        // One-shot failure: this node request answers NULL. The allocation-error state the
        // crate's `CRYPTO_malloc` allocates in response is then allowed through (a permanent
        // failure would recurse).
        return ptr::null_mut();
    }
    MALLOCS.fetch_add(1, Ordering::SeqCst);
    {
        let mut sizes = SIZES.lock().unwrap();
        if sizes.len() < 256 {
            sizes.push(n as u64);
        }
    }
    // SAFETY: `malloc` has no preconditions.
    unsafe { malloc(n) }
}

unsafe extern "C" fn hook_realloc(
    p: *mut c_void,
    n: usize,
    _file: *const c_char,
    _line: c_int,
) -> *mut c_void {
    // SAFETY: `p` is NULL or a block from `hook_malloc`.
    unsafe { realloc(p, n) }
}

unsafe extern "C" fn hook_free(p: *mut c_void, _file: *const c_char, _line: c_int) {
    FREES.fetch_add(1, Ordering::SeqCst);
    // SAFETY: `p` is NULL or a block from `hook_malloc`.
    unsafe { free(p) }
}

/// Value blocks: an 8-byte block whose first byte is the tag, so a `get` result is reported as
/// the tag it holds rather than as a pointer (which differs run to run).
struct Values {
    blocks: Vec<*mut c_void>,
    tags: Vec<u8>,
}

impl Values {
    fn alloc() -> Values {
        let mut v = Values {
            blocks: Vec::new(),
            tags: Vec::new(),
        };
        // Seven value blocks, tags 1..=7.
        for t in 1u8..=7 {
            let p = CRYPTO_malloc(8, c"probe".as_ptr(), 1);
            assert!(!p.is_null());
            // SAFETY: `p` is a fresh 8-byte block.
            unsafe { (p as *mut u8).write(t) };
            v.blocks.push(p);
            v.tags.push(t);
        }
        v
    }

    fn block(&self, tag: u8) -> *mut c_void {
        self.blocks[(tag - 1) as usize]
    }

    /// The tag a live value pointer holds: -1 for NULL, -2 for a foreign pointer.
    fn tag_of(&self, p: *mut c_void) -> i32 {
        if p.is_null() {
            return -1;
        }
        for (i, &b) in self.blocks.iter().enumerate() {
            if b == p {
                return self.tags[i] as i32;
            }
        }
        -2
    }
}

static ORDER: Mutex<Vec<u64>> = Mutex::new(Vec::new());

unsafe fn order_note(_idx: OsslUintMax, val: *mut c_void, arg: *mut c_void) {
    // `arg` is the `Values`; record tag+1 so a null value is 0.
    // SAFETY: `arg` is the `*const Values` this harness passes.
    let values = unsafe { &*(arg as *const Values) };
    let tag = values.tag_of(val);
    ORDER.lock().unwrap().push((tag + 1) as u64);
}

/// The differential transcript. `SPARSE_ARRAY_PROBE=1` runs it; otherwise it is a no-op so the
/// ordinary test suite never has its process-global allocator replaced.
#[test]
fn sparse_array_under_installed_allocator() {
    if std::env::var("SPARSE_ARRAY_PROBE").as_deref() != Ok("1") {
        eprintln!("sparse_array_under_installed_allocator: skipped (set SPARSE_ARRAY_PROBE=1)");
        return;
    }

    // Install the caller's allocator first: this is the only order the seam accepts.
    // SAFETY: the hooks are valid for the lifetime of this process and every later CRYPTO
    // allocation routes through them; this is the only test in its process.
    let installed =
        unsafe { CRYPTO_set_mem_functions(Some(hook_malloc), Some(hook_realloc), Some(hook_free)) };

    let values = Values::alloc();

    let sa = ossl_sa_new();
    let mut out = format!(
        "SPARSE_JSON {{\"impl\":\"openssl-rs\",\"installed\":{installed},\"new\":{},",
        !sa.is_null()
    );

    // Insert / replace / remove / depth growth / the numeric boundary. `tag == 0` is a removal.
    let ops: [(u64, u8); 8] = [
        (5, 1),
        (0, 2),
        (0x10, 3),
        (0x100, 4),
        (5, 5),
        (0x10, 0),
        (u64::MAX, 6),
        (1 << 60, 7),
    ];
    let mut set_ret: Vec<i32> = Vec::new();
    for &(n, tag) in &ops {
        let val = if tag == 0 {
            ptr::null_mut()
        } else {
            values.block(tag)
        };
        // SAFETY: `sa` is live.
        set_ret.push(unsafe { ossl_sa_set(sa, n, val) });
    }
    out += "\"set_ret\":[";
    for (i, r) in set_ret.iter().enumerate() {
        out += &format!("{}{}", if i == 0 { "" } else { "," }, r);
    }
    out += "],";

    // SAFETY: `sa` is live.
    let num0 = unsafe { ossl_sa_num(sa) };
    out += &format!("\"num\":{num0},");

    let gets: [u64; 7] = [5, 0, 0x10, 0x100, 1 << 60, u64::MAX, 17];
    out += "\"get\":[";
    for (i, &n) in gets.iter().enumerate() {
        // SAFETY: `sa` is live.
        let p = unsafe { ossl_sa_get(sa, n) };
        out += &format!("{}{}", if i == 0 { "" } else { "," }, values.tag_of(p));
    }
    out += "],";

    ORDER.lock().unwrap().clear();
    // SAFETY: `sa` is live; `order_note` is this harness's own Rust-ABI callback and `arg` is
    // the `Values` it reads.
    unsafe {
        ossl_sa_doall_arg(
            sa,
            Some(order_note),
            (&values as *const Values).cast_mut().cast(),
        )
    };
    out += "\"order\":[";
    for (i, o) in ORDER.lock().unwrap().iter().enumerate() {
        out += &format!("{}{}", if i == 0 { "" } else { "," }, o);
    }
    out += "],";

    // Release values, nodes and header **before** reading the counters, so the recorded
    // comparison covers the release path too -- the value, node and header frees -- not just
    // construction. This closes the measurement gap where `free` read 0 on both sides simply
    // because neither side had been asked to release anything yet.
    // SAFETY: `sa` is live and this harness owns every value.
    unsafe { ossl_sa_free_leaves(sa) };

    {
        let malloc_count = MALLOCS.load(Ordering::SeqCst);
        let free_count = FREES.load(Ordering::SeqCst);
        let sizes = SIZES.lock().unwrap();
        out += &format!("\"alloc\":{{\"malloc\":{malloc_count},\"free\":{free_count},\"sizes\":[");
        for (i, s) in sizes.iter().enumerate() {
            out += &format!("{}{}", if i == 0 { "" } else { "," }, s);
        }
        out += "]},";
    }

    MALLOCS.store(0, Ordering::SeqCst);
    FREES.store(0, Ordering::SeqCst);
    // Allocation-failure injection: a fresh array whose first growth node is refused.
    // SAFETY: `f` is a live array this harness owns and `FAIL_NEXT` steers the hook.
    let fail = unsafe {
        let f = ossl_sa_new();
        FAIL_NEXT.store(true, Ordering::SeqCst);
        let r = ossl_sa_set(f, 0x100, values.block(1));
        let n = ossl_sa_num(f);
        let g = ossl_sa_get(f, 0x100);
        let levels = if f.is_null() { -1 } else { (*f).levels };
        FAIL_NEXT.store(false, Ordering::SeqCst);
        let r2 = ossl_sa_set(f, 0x100, values.block(1));
        let retry_num = ossl_sa_num(f);
        // Release the injected-failure array's nodes and header **before** reading the counters,
        // so the failure sequence's cleanup is a measured fact too. The value block is the
        // caller's and `ossl_sa_free` does not release it.
        ossl_sa_free(f);
        let malloc_count = MALLOCS.load(Ordering::SeqCst);
        let free_count = FREES.load(Ordering::SeqCst);
        format!(
            "\"fail\":{{\"set_ret\":{r},\"num\":{n},\"get_null\":{},\"levels\":{levels},\
             \"retry_ret\":{r2},\"retry_num\":{retry_num},\
             \"malloc\":{malloc_count},\"free\":{free_count}}},",
            g.is_null()
        )
    };
    out += &fail;
    out += &format!("\"num\":{num0}}}");
    println!("{out}");

    // The one fact the transcript keeps free of the allocator: the failure answer.
    assert_eq!(set_ret, vec![1, 1, 1, 1, 1, 1, 1, 1]);
    assert_eq!(num0, 5);
    let _ = values; // kept alive for the whole run; the array does not own these for plain free
}
