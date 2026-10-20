//! Phase 25 X.509 policy-tree differential harness: the policy graph under a caller-installed
//! allocator.
//!
//! This is test-only tooling, not product. `forensics/tools/ms_x509_policy_court.py` runs it
//! against the crate and the matching C probe (`courts/phase25/rt_x509_policy_differential.c`)
//! against the admitted authority, and compares the two transcripts: the `X509_policy_check`
//! return word over the NULL -> mapped-policy certificate stacks, the built tree's shape and
//! traversal order, the pointer identity of the `get0` accessors, the allocation-hook
//! observations over the graph's construction **and** release, the injected failure answer, the
//! CVE-2023-0464 node cap and the certificate refcounts.
//!
//! It lives as a cargo **example**, not a `src/` module: the Phase-25 seal is published, and its
//! `MS-SOURCE-CENSUS`/`MS-OWNERSHIP-PLANES` courts census `src/**` and `tests/**` exactly, so a
//! new in-crate harness would add globals and contexts the sealed artefacts do not record. The
//! example drives the crate through its **public** surface -- the exported `#[no_mangle]`
//! accessors and `CRYPTO_set_mem_functions` -- exactly as the C probe drives the authority's.
//!
//! The harness installs the crate's allocator seam (`CRYPTO_set_mem_functions`) with counting,
//! size-recording, failure-injecting hooks and drives `X509_policy_check` exactly as the C probe
//! drives the authority's. Installing the allocator is a process-global act, so the harness is a
//! no-op unless `X509_POLICY_PROBE=1` is set in the environment; the court runs it with that
//! variable, so it is the only consumer in its process.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::ptr;
use core::sync::atomic::{AtomicI64, Ordering};

use std::ffi::CString;
use std::sync::Mutex;

use openssl_rs::asn1::prim::ASN1_OBJECT_free;
use openssl_rs::runtime::mem::CRYPTO_set_mem_functions;
use openssl_rs::runtime::obj::{Asn1Object, OBJ_obj2txt, OBJ_txt2obj};
use openssl_rs::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OpenSslStack,
};
use openssl_rs::x509::pcy_lib::{X509PolicyNode, X509PolicyTree};
use openssl_rs::x509::pcy_tree::{X509_policy_check, X509_policy_tree_free};
use openssl_rs::x509::v3_cpols::{POLICYINFO_free, POLICYINFO_new, PolicyInfo};
use openssl_rs::x509::v3_pmaps::{POLICY_MAPPING_free, POLICY_MAPPING_new, PolicyMapping};
use openssl_rs::x509::x509_ext::X509_add1_ext_i2d;
use openssl_rs::x509::x_x509::{X509_free, X509_new, X509};

extern "C" {
    fn malloc(n: usize) -> *mut c_void;
    fn realloc(p: *mut c_void, n: usize) -> *mut c_void;
    fn free(p: *mut c_void);
}

/// `NID_certificate_policies` (`include/openssl/obj_mac.h`); the crate keeps it `pub(crate)`.
const NID_CERTIFICATE_POLICIES: c_int = 89;
/// `NID_policy_mappings` (`include/openssl/obj_mac.h`); the crate keeps it `pub(crate)`.
const NID_POLICY_MAPPINGS: c_int = 747;
/// `X509_V_FLAG_EXPLICIT_POLICY` — `include/openssl/x509_vfy.h.in:355`.
const X509_V_FLAG_EXPLICIT_POLICY: c_uint = 0x100;
/// The crate's `offset_of!(X509, references)` (`src/x509/x_x509.rs`).
const X509_REFERENCES_OFFSET: usize = 192;
/// `sizeof(X509_POLICY_NODE)`: the failure injection refuses the first allocation of exactly this
/// size inside the check window, which is the root anyPolicy node (the tree block is 64, the levels
/// array is `nlevel * 32`, the datum is 32, the stack header is not routed through the hook).
const NODE_SIZE: i64 = 24;

static MALLOCS: AtomicI64 = AtomicI64::new(0);
static FREES: AtomicI64 = AtomicI64::new(0);
static FAIL_SIZE: AtomicI64 = AtomicI64::new(-1);
static SIZES: Mutex<Vec<u64>> = Mutex::new(Vec::new());

unsafe extern "C" fn hook_malloc(n: usize, _file: *const c_char, _line: c_int) -> *mut c_void {
    if FAIL_SIZE.load(Ordering::SeqCst) == n as i64 {
        // One-shot failure: the node request answers NULL and the block is not counted. The error
        // state the crate's `CRYPTO_malloc` then raises through is a static structure, so it
        // allocates nothing here.
        FAIL_SIZE.store(-1, Ordering::SeqCst);
        return ptr::null_mut();
    }
    MALLOCS.fetch_add(1, Ordering::SeqCst);
    {
        let mut sizes = SIZES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if sizes.len() < 512 {
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

fn reset_counts() {
    MALLOCS.store(0, Ordering::SeqCst);
    FREES.store(0, Ordering::SeqCst);
    SIZES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
}

fn refs_of(x: *mut X509) -> c_int {
    // SAFETY: `x` is live; the offset is the crate's own `offset_of!(X509, references)`.
    unsafe { *((x as *const u8).add(X509_REFERENCES_OFFSET) as *const c_int) }
}

unsafe extern "C" fn policyinfo_free_void(p: *mut c_void) {
    // SAFETY: `p` is a `PolicyInfo` from `POLICYINFO_new`.
    unsafe { POLICYINFO_free(p.cast::<PolicyInfo>()) };
}

unsafe extern "C" fn policy_mapping_free_void(p: *mut c_void) {
    // SAFETY: `p` is a `PolicyMapping` from `POLICY_MAPPING_new`.
    unsafe { POLICY_MAPPING_free(p.cast::<PolicyMapping>()) };
}

unsafe extern "C" fn asn1_object_free_void(p: *mut c_void) {
    // SAFETY: `p` is an `ASN1_OBJECT`.
    unsafe { ASN1_OBJECT_free(p.cast::<Asn1Object>()) };
}

unsafe fn cert_with_policies(oids: &[&str]) -> *mut X509 {
    // SAFETY: every call below is a live-object FFI call.
    unsafe {
        let x = X509_new();
        if x.is_null() {
            return ptr::null_mut();
        }
        let cps = OPENSSL_sk_new_null();
        if cps.is_null() {
            X509_free(x);
            return ptr::null_mut();
        }
        for oid in oids {
            let pi = POLICYINFO_new();
            if pi.is_null() {
                OPENSSL_sk_pop_free(cps, Some(policyinfo_free_void));
                X509_free(x);
                return ptr::null_mut();
            }
            let c = CString::new(*oid).unwrap_or_default();
            (*pi).policyid = OBJ_txt2obj(c.as_ptr(), 1);
            if (*pi).policyid.is_null() || OPENSSL_sk_push(cps, pi.cast::<c_void>()) == 0 {
                POLICYINFO_free(pi);
                OPENSSL_sk_pop_free(cps, Some(policyinfo_free_void));
                X509_free(x);
                return ptr::null_mut();
            }
        }
        if X509_add1_ext_i2d(x, NID_CERTIFICATE_POLICIES, cps.cast::<c_void>(), 0, 0) == 0 {
            OPENSSL_sk_pop_free(cps, Some(policyinfo_free_void));
            X509_free(x);
            return ptr::null_mut();
        }
        OPENSSL_sk_pop_free(cps, Some(policyinfo_free_void));
        x
    }
}

unsafe fn cert_with_one_policy(oid: &str) -> *mut X509 {
    // SAFETY: forwarded.
    unsafe { cert_with_policies(&[oid]) }
}

unsafe fn cert_with_mapping(pol: &str, from: &str, to: &str) -> *mut X509 {
    // SAFETY: every call below is a live-object FFI call.
    unsafe {
        let x = cert_with_one_policy(pol);
        if x.is_null() {
            return ptr::null_mut();
        }
        let maps = OPENSSL_sk_new_null();
        let pm = POLICY_MAPPING_new();
        if maps.is_null() || pm.is_null() {
            OPENSSL_sk_free(maps);
            POLICY_MAPPING_free(pm);
            X509_free(x);
            return ptr::null_mut();
        }
        let cf = CString::new(from).unwrap_or_default();
        let ct = CString::new(to).unwrap_or_default();
        (*pm).issuerDomainPolicy = OBJ_txt2obj(cf.as_ptr(), 1);
        (*pm).subjectDomainPolicy = OBJ_txt2obj(ct.as_ptr(), 1);
        if (*pm).issuerDomainPolicy.is_null()
            || (*pm).subjectDomainPolicy.is_null()
            || OPENSSL_sk_push(maps, pm.cast::<c_void>()) == 0
        {
            POLICY_MAPPING_free(pm);
            OPENSSL_sk_free(maps);
            X509_free(x);
            return ptr::null_mut();
        }
        if X509_add1_ext_i2d(x, NID_POLICY_MAPPINGS, maps.cast::<c_void>(), 0, 0) == 0 {
            OPENSSL_sk_pop_free(maps, Some(policy_mapping_free_void));
            X509_free(x);
            return ptr::null_mut();
        }
        OPENSSL_sk_pop_free(maps, Some(policy_mapping_free_void));
        x
    }
}

unsafe fn cert_with_npolicies(n: i32) -> *mut X509 {
    // SAFETY: every call below is a live-object FFI call.
    unsafe {
        let x = X509_new();
        if x.is_null() {
            return ptr::null_mut();
        }
        let cps = OPENSSL_sk_new_null();
        if cps.is_null() {
            X509_free(x);
            return ptr::null_mut();
        }
        for i in 0..n {
            let pi = POLICYINFO_new();
            if pi.is_null() {
                OPENSSL_sk_pop_free(cps, Some(policyinfo_free_void));
                X509_free(x);
                return ptr::null_mut();
            }
            let c = CString::new(format!("1.2.3.4.{}", i + 1)).unwrap_or_default();
            (*pi).policyid = OBJ_txt2obj(c.as_ptr(), 1);
            if (*pi).policyid.is_null() || OPENSSL_sk_push(cps, pi.cast::<c_void>()) == 0 {
                POLICYINFO_free(pi);
                OPENSSL_sk_pop_free(cps, Some(policyinfo_free_void));
                X509_free(x);
                return ptr::null_mut();
            }
        }
        if X509_add1_ext_i2d(x, NID_CERTIFICATE_POLICIES, cps.cast::<c_void>(), 0, 0) == 0 {
            OPENSSL_sk_pop_free(cps, Some(policyinfo_free_void));
            X509_free(x);
            return ptr::null_mut();
        }
        OPENSSL_sk_pop_free(cps, Some(policyinfo_free_void));
        x
    }
}

unsafe fn push_cert(stack: *mut OpenSslStack, x: *mut X509) {
    // SAFETY: `stack` is live; `x` is a live certificate.
    unsafe { OPENSSL_sk_push(stack, x.cast::<c_void>()) };
}

fn oid_text(o: *const Asn1Object) -> String {
    if o.is_null() {
        return String::new();
    }
    let mut buf = [0 as c_char; 160];
    // SAFETY: `buf` is writable for 160 bytes; `o` is live.
    let n = unsafe { OBJ_obj2txt(buf.as_mut_ptr(), 160, o, 1) };
    if n <= 0 {
        return String::new();
    }
    // SAFETY: `OBJ_obj2txt` wrote a NUL-terminated string into `buf`.
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

unsafe fn shape_json(name: &str, tree: *mut X509PolicyTree, ret: c_int, expl: c_int) -> String {
    // SAFETY: `tree` is NULL or live.
    unsafe {
        let mut out = format!(
            "{{\"name\":\"{name}\",\"ret\":{ret},\"expl\":{expl},\"tree\":{}",
            if tree.is_null() { 0 } else { 1 }
        );
        let levels = openssl_rs::x509::pcy_lib::X509_policy_tree_level_count(tree);
        out += &format!(",\"levels\":{levels}");
        let pol = OPENSSL_sk_num(openssl_rs::x509::pcy_lib::X509_policy_tree_get0_policies(
            tree,
        ));
        let user =
            OPENSSL_sk_num(openssl_rs::x509::pcy_lib::X509_policy_tree_get0_user_policies(tree));
        out += &format!(",\"pol\":{pol},\"user\":{user}");
        out += ",\"lc\":[";
        for i in 0..levels {
            let lvl = openssl_rs::x509::pcy_lib::X509_policy_tree_get0_level(tree, i);
            out += &format!(
                "{}{}",
                if i == 0 { "" } else { "," },
                openssl_rs::x509::pcy_lib::X509_policy_level_node_count(lvl)
            );
        }
        out += "],\"order\":[";
        let mut first = true;
        for i in 0..levels {
            let lvl = openssl_rs::x509::pcy_lib::X509_policy_tree_get0_level(tree, i);
            let n = openssl_rs::x509::pcy_lib::X509_policy_level_node_count(lvl);
            for j in 0..n {
                let node = openssl_rs::x509::pcy_lib::X509_policy_level_get0_node(lvl, j);
                let o = openssl_rs::x509::pcy_lib::X509_policy_node_get0_policy(node);
                out += &format!("{}\"{}\"", if first { "" } else { "," }, oid_text(o));
                first = false;
            }
        }
        out += "]}";
        out
    }
}

struct Ident {
    nodes: c_int,
    parents: c_int,
    resolved: c_int,
    stable: c_int,
}

unsafe fn measure_identity(tree: *mut X509PolicyTree) -> Ident {
    // SAFETY: `tree` is live; every accessor is a live-object FFI call.
    unsafe {
        let levels = openssl_rs::x509::pcy_lib::X509_policy_tree_level_count(tree);
        let mut id = Ident {
            nodes: 0,
            parents: 0,
            resolved: 0,
            stable: 1,
        };
        for i in 0..levels {
            let lvl = openssl_rs::x509::pcy_lib::X509_policy_tree_get0_level(tree, i);
            let n = openssl_rs::x509::pcy_lib::X509_policy_level_node_count(lvl);
            for j in 0..n {
                let node = openssl_rs::x509::pcy_lib::X509_policy_level_get0_node(lvl, j);
                let par = openssl_rs::x509::pcy_lib::X509_policy_node_get0_parent(node);
                id.nodes += 1;
                if openssl_rs::x509::pcy_lib::X509_policy_level_get0_node(lvl, j) != node {
                    id.stable = 0;
                }
                if !par.is_null() {
                    id.parents += 1;
                    let mut ok = false;
                    if i > 0 {
                        let below =
                            openssl_rs::x509::pcy_lib::X509_policy_tree_get0_level(tree, i - 1);
                        let m = openssl_rs::x509::pcy_lib::X509_policy_level_node_count(below);
                        for k in 0..m {
                            if std::ptr::eq(
                                openssl_rs::x509::pcy_lib::X509_policy_level_get0_node(below, k)
                                    as *const X509PolicyNode,
                                par,
                            ) {
                                ok = true;
                                break;
                            }
                        }
                    }
                    if ok {
                        id.resolved += 1;
                    }
                }
            }
        }
        id
    }
}

fn main() {
    if std::env::var("X509_POLICY_PROBE").as_deref() != Ok("1") {
        eprintln!("x509_policy_differential: skipped (set X509_POLICY_PROBE=1)");
        return;
    }

    // SAFETY: the hooks are valid for the lifetime of this process and every later CRYPTO
    // allocation routes through them; the harness is the only consumer in its process.
    let installed =
        unsafe { CRYPTO_set_mem_functions(Some(hook_malloc), Some(hook_realloc), Some(hook_free)) };

    let mut out = format!("X509_POLICY_JSON {{\"impl\":\"openssl-rs\",\"installed\":{installed},");
    out += "\"cases\":[";

    // SAFETY: the whole sequence drives live objects this harness owns.
    unsafe {
        let mut tree: *mut X509PolicyTree;
        let mut expl: c_int;
        let mut ret: c_int;
        let oids_stack: *mut OpenSslStack;

        // 1. NULL certs.
        {
            tree = ptr::null_mut();
            expl = -1;
            ret = X509_policy_check(
                &raw mut tree,
                &raw mut expl,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            );
            out += &shape_json("null_certs", tree, ret, expl);
            X509_policy_tree_free(tree);
        }

        // 2. Empty cert stack.
        {
            let c = OPENSSL_sk_new_null();
            out += ",";
            tree = ptr::null_mut();
            expl = -1;
            ret = X509_policy_check(&raw mut tree, &raw mut expl, c, ptr::null_mut(), 0);
            out += &shape_json("empty_certs", tree, ret, expl);
            X509_policy_tree_free(tree);
            OPENSSL_sk_free(c);
        }

        // 3. One trust anchor.
        {
            let ta = X509_new();
            let c = OPENSSL_sk_new_null();
            push_cert(c, ta);
            out += ",";
            tree = ptr::null_mut();
            expl = -1;
            ret = X509_policy_check(&raw mut tree, &raw mut expl, c, ptr::null_mut(), 0);
            out += &shape_json("one_ta", tree, ret, expl);
            X509_policy_tree_free(tree);
            OPENSSL_sk_free(c);
            X509_free(ta);
        }

        // 4. Two policy-free certs.
        {
            let a = X509_new();
            let b = X509_new();
            let c = OPENSSL_sk_new_null();
            push_cert(c, a);
            push_cert(c, b);
            out += ",";
            tree = ptr::null_mut();
            expl = -1;
            ret = X509_policy_check(&raw mut tree, &raw mut expl, c, ptr::null_mut(), 0);
            out += &shape_json("no_policies", tree, ret, expl);
            X509_policy_tree_free(tree);
            OPENSSL_sk_free(c);
            X509_free(a);
            X509_free(b);
        }

        // 5. Two policy-free certs under X509_V_FLAG_EXPLICIT_POLICY.
        {
            let a = X509_new();
            let b = X509_new();
            let c = OPENSSL_sk_new_null();
            push_cert(c, a);
            push_cert(c, b);
            out += ",";
            tree = ptr::null_mut();
            expl = -1;
            ret = X509_policy_check(
                &raw mut tree,
                &raw mut expl,
                c,
                ptr::null_mut(),
                X509_V_FLAG_EXPLICIT_POLICY,
            );
            out += &shape_json("explicit_empty", tree, ret, expl);
            X509_policy_tree_free(tree);
            OPENSSL_sk_free(c);
            X509_free(a);
            X509_free(b);
        }

        // 6. A real leaf policy over a trust anchor. This is the success window: the counters are
        //    read after `X509_policy_tree_free`, so the recorded comparison covers construction and
        //    release; the teardown window then isolates the certificate free.
        let ident: Ident;
        let (ref_fresh, ref_after, ref_freed);
        let (win_mallocs, win_frees, win_sizes);
        let (cl_mallocs, cl_frees);
        {
            let leaf = cert_with_one_policy("1.2.3.4");
            let ta = X509_new();
            let c = OPENSSL_sk_new_null();
            push_cert(c, leaf);
            push_cert(c, ta);
            ref_fresh = refs_of(leaf);
            reset_counts();
            tree = ptr::null_mut();
            expl = -1;
            ret = X509_policy_check(&raw mut tree, &raw mut expl, c, ptr::null_mut(), 0);
            ref_after = refs_of(leaf);
            ident = measure_identity(tree);
            out += ",";
            out += &shape_json("single_policy", tree, ret, expl);
            X509_policy_tree_free(tree);
            ref_freed = refs_of(leaf);
            win_mallocs = MALLOCS.load(Ordering::SeqCst);
            win_frees = FREES.load(Ordering::SeqCst);
            win_sizes = SIZES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            // The teardown window: freeing the leaf releases the per-cert policy cache on the
            // authority (`X509_free` -> `ossl_policy_cache_free`), which the crate withholds.
            reset_counts();
            X509_free(leaf);
            X509_free(ta);
            cl_mallocs = MALLOCS.load(Ordering::SeqCst);
            cl_frees = FREES.load(Ordering::SeqCst);
            OPENSSL_sk_free(c);
        }

        // 7. The same leaf, asking for the user set to contain 1.2.3.4.
        {
            let leaf = cert_with_one_policy("1.2.3.4");
            let ta = X509_new();
            let c = OPENSSL_sk_new_null();
            oids_stack = OPENSSL_sk_new_null();
            push_cert(c, leaf);
            push_cert(c, ta);
            let oid = CString::new("1.2.3.4").unwrap_or_default();
            OPENSSL_sk_push(oids_stack, OBJ_txt2obj(oid.as_ptr(), 1).cast::<c_void>());
            out += ",";
            tree = ptr::null_mut();
            expl = -1;
            ret = X509_policy_check(&raw mut tree, &raw mut expl, c, oids_stack, 0);
            out += &shape_json("user_policy", tree, ret, expl);
            X509_policy_tree_free(tree);
            OPENSSL_sk_pop_free(oids_stack, Some(asn1_object_free_void));
            OPENSSL_sk_free(c);
            X509_free(leaf);
            X509_free(ta);
        }

        // 8. The mapped-policy chain: leaf {1.2.3.4, 1.2.3.6}, an intermediate mapping
        //    1.2.3.4 -> 1.2.3.5, and a trust anchor.
        {
            let leaf = cert_with_policies(&["1.2.3.4", "1.2.3.6"]);
            let inter = cert_with_mapping("1.2.3.4", "1.2.3.4", "1.2.3.5");
            let ta = X509_new();
            let c = OPENSSL_sk_new_null();
            push_cert(c, leaf);
            push_cert(c, inter);
            push_cert(c, ta);
            out += ",";
            tree = ptr::null_mut();
            expl = -1;
            ret = X509_policy_check(&raw mut tree, &raw mut expl, c, ptr::null_mut(), 0);
            out += &shape_json("mapped_policy", tree, ret, expl);
            X509_policy_tree_free(tree);
            OPENSSL_sk_free(c);
            X509_free(leaf);
            X509_free(inter);
            X509_free(ta);
        }

        out += "],";

        out += &format!(
            "\"ident\":{{\"nodes\":{},\"parents\":{},\"resolved\":{},\"stable\":{}}},",
            ident.nodes, ident.parents, ident.resolved, ident.stable
        );

        out += &format!("\"alloc\":{{\"malloc\":{win_mallocs},\"free\":{win_frees},\"sizes\":[");
        for (i, s) in win_sizes.iter().enumerate() {
            out += &format!("{}{}", if i == 0 { "" } else { "," }, s);
        }
        out += "]},";

        out += &format!("\"cleanup\":{{\"malloc\":{cl_mallocs},\"free\":{cl_frees}}},");

        // Allocation-failure injection: refuse the first allocation of the node's own size in a
        // fresh check window. `ossl_policy_level_add_node` must propagate NULL, so
        // `X509_policy_check` answers INTERNAL with a NULL tree.
        {
            let leaf = cert_with_one_policy("1.2.3.4");
            let ta = X509_new();
            let c = OPENSSL_sk_new_null();
            push_cert(c, leaf);
            push_cert(c, ta);
            reset_counts();
            FAIL_SIZE.store(NODE_SIZE, Ordering::SeqCst);
            tree = ptr::null_mut();
            expl = -1;
            ret = X509_policy_check(&raw mut tree, &raw mut expl, c, ptr::null_mut(), 0);
            let levels = openssl_rs::x509::pcy_lib::X509_policy_tree_level_count(tree);
            out += &format!(
                "\"fail\":{{\"ret\":{ret},\"tree\":{},\"levels\":{levels},\"expl\":{expl},\
                 \"malloc\":{},\"free\":{}}},",
                if tree.is_null() { 0 } else { 1 },
                MALLOCS.load(Ordering::SeqCst),
                FREES.load(Ordering::SeqCst)
            );
            X509_policy_tree_free(tree);
            OPENSSL_sk_free(c);
            X509_free(leaf);
            X509_free(ta);
        }

        // CVE-2023-0464 cap: a leaf with 1100 distinct policies overruns `node_maximum = 1000`.
        {
            let leaf = cert_with_npolicies(1100);
            let ta = X509_new();
            let c = OPENSSL_sk_new_null();
            push_cert(c, leaf);
            push_cert(c, ta);
            tree = ptr::null_mut();
            expl = -1;
            ret = if leaf.is_null() {
                -99
            } else {
                X509_policy_check(&raw mut tree, &raw mut expl, c, ptr::null_mut(), 0)
            };
            out += &format!(
                "\"cap\":{{\"ret\":{ret},\"tree\":{}}},",
                if tree.is_null() { 0 } else { 1 }
            );
            X509_policy_tree_free(tree);
            OPENSSL_sk_free(c);
            X509_free(leaf);
            X509_free(ta);
        }

        // The stack-container control: the same bare `OPENSSL_sk_new_null`/push/free the C probe
        // drives. The crate's container is a `Box`/`Vec`, so the hook sees nothing.
        {
            let marker = (&raw const MALLOCS).cast::<c_void>().cast_mut();
            reset_counts();
            let sk = OPENSSL_sk_new_null();
            OPENSSL_sk_push(sk, marker);
            OPENSSL_sk_free(sk);
            out += &format!(
                "\"stacks\":{{\"malloc\":{},\"free\":{}}},",
                MALLOCS.load(Ordering::SeqCst),
                FREES.load(Ordering::SeqCst)
            );
        }

        // The ASN1-object control: a bare dynamic `OBJ_txt2obj` under the installed hook. The crate
        // allocates the object through libc `malloc`, so the hook sees nothing.
        {
            let c = CString::new("1.2.3.4").unwrap_or_default();
            reset_counts();
            let o = OBJ_txt2obj(c.as_ptr(), 1);
            ASN1_OBJECT_free(o);
            out += &format!(
                "\"objects\":{{\"malloc\":{},\"free\":{}}},",
                MALLOCS.load(Ordering::SeqCst),
                FREES.load(Ordering::SeqCst)
            );
        }

        out += &format!(
            "\"refcount\":{{\"fresh\":{ref_fresh},\"after\":{ref_after},\"freed\":{ref_freed}}}"
        );

        out += "}";
        println!("{out}");

        assert_eq!(installed, 1);
    }
}
