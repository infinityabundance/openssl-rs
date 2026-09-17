//! Phase 7.3g — the legacy method registry's two adders.
//!
//! `crypto/evp/names.c`'s `EVP_add_cipher` and `EVP_add_digest`, which are the whole of the
//! *writing* side of the legacy table that 7.3b and 7.3d read: `EVP_CIPHER_get0_name`'s legacy
//! fallback and `EVP_MD_fetch`'s `set_legacy_nid` both look a method up in the `OBJ_NAME`
//! database, and these two functions are what puts one there.
//!
//! ## Why these are here and the wrappers they exist for are not
//!
//! 7.3g's row hands the legacy `EVP_aes_*`, `EVP_des_*`, `EVP_sha*` and the rest of the one
//! hundred and sixty-odd statics to **Phase 13**, with the primitive unit named, because each one
//! wraps a low-level primitive implementation (`AES_encrypt`, `SHA256_Update`, …) that this stratum
//! does not have and that no provider can lend it. What can be done here *is* done, and these two
//! are the part that can: **an adder takes the method from its caller**. Nothing in either body
//! reads a primitive; the object it registers was built somewhere else, and on this side of the
//! hand-off that somewhere is always a caller's.
//!
//! That is also why the pair is not a formality. `EVP_add_cipher` is what makes
//! `EVP_get_cipherbyname` answer at all, and `EVP_get_cipherbyname` is handed to Phase 13 *because*
//! the table is empty without it: a court can observe the function and not its answer, so the row
//! that owns the answer owns the function.
//!
//! ## The three details a transcription gets wrong
//!
//!   * **`EVP_add_cipher` guards a NULL and `EVP_add_digest` does not.** `EVP_add_digest` reads
//!     `md->type` on its first line; a NULL there is a fault in the authority and this crate does
//!     not reproduce it (`docs/SECURITY_DIVERGENCE_POLICY.md`), so the guard is present and the
//!     difference is recorded rather than smoothed over. The *observable* difference between the
//!     two functions is that one of them is callable with a NULL and the other is not.
//!   * **the return value is the *last* one, not a conjunction.** `EVP_add_cipher` answers what the
//!     second `OBJ_NAME_add` answered, and short-circuits on the first; so a short name that is
//!     already taken and a long name that is free is a **0**, and the long name is never attempted.
//!     A transcription that ANDed the two results would attempt both and answer the same 0.
//!   * **`EVP_add_digest` registers the pkey alias twice, under the short *and* long name of the
//!     pkey NID**, and only when the two NIDs disagree. An `EVP_MD` whose `pkey_type` is zero — or
//!     equal to its `type` — gets neither, which is every provider method and most legacy ones.
//!
//! ## The two lookups, and why they are here after all
//!
//! `EVP_get_cipherbyname` and `EVP_get_digestbyname` and their `_ex` halves are `names.c`'s the
//! same way the adders are, and the first reading of 7.3g handed them to Phase 13 on the argument
//! that **their whole answer is a lookup in the table the wrappers fill** -- so a court could
//! observe the function and not its result, and the row that owns the answer owns the function.
//!
//! That argument is sound about the *table* and wrong about the *functions*, and `RT-EVP-NAMES` is
//! what settled it. Three things follow from reading the bodies again:
//!
//!   * the legacy lookup is only the **first** of three steps. A miss falls through to the namemap,
//!     and a name the namemap does not know is *fetched* -- with `ERR_set_mark` around the fetch, so
//!     that a failed resolution leaves the error queue exactly as it found it -- and then looked up
//!     again. Every one of those pieces is this stratum's or an earlier one's;
//!   * a caller that has added a method with `EVP_add_cipher` gets it back **by name**, which is the
//!     whole point of the pair, and it needs no Phase-13 primitive;
//!   * what Phase 13 changes is which names the first step finds. That is a *contents* divergence,
//!     already recorded; refusing to write a function because one of its inputs is another stratum's
//!     contents would put this crate's `EVP_get_cipherbyname` in the same class as its tables.
//!
//! ## What is not here
//!
//! `evp_cleanup_int` is `names.c`'s too, and it is **owed to Phase 8**. Its body is four
//! `OBJ_NAME_cleanup` calls, `EVP_PBE_cleanup`, `OBJ_sigid_free` and `evp_app_cleanup_int`; the
//! first six are landed -- `EVP_PBE_cleanup` landed with 7.4c's PBE remainder (D192), which is the
//! dependency this note was written against -- and the seventh is Phase 8's, because
//! `evp_app_cleanup_int` pops the application-supplied `EVP_PKEY_METHOD` registry that
//! `EVP_PKEY_meth_find` searches. It is recorded in `forensics/prerequisites.json` with that
//! dependency named rather than stubbed, and D196 retargets the row from this stratum to Phase 8.
//!
//! `EVP_add_alg_module` is `crypto/evp/evp_cnf.c`'s, a 7.4 unit: its body is two lines of
//! `CONF_module_add`, but the module callback it registers reads the configuration through
//! `X509V3_get_value_bool` (`crypto/x509/v3_utl.c:266`, Phase 11's), so the pair lands together
//! rather than half of it here. It is one of the ledger's reasoned deferrals to Phase 11; D196
//! records the two lines and the coordinate. `EVP_add_cipher_alias` and `EVP_add_digest_alias` are **macros** over
//! `OBJ_NAME_add` in `evp.h` and have no export to transcribe.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::context::namemap::{
    ossl_namemap_doall_names, ossl_namemap_name2num, ossl_namemap_stored,
};
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EvpCipher, OBJ_NAME_TYPE_CIPHER_METH};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EvpMd, OBJ_NAME_TYPE_MD_METH};
use crate::runtime::err::{ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::init::{
    OPENSSL_init_crypto, OPENSSL_INIT_ADD_ALL_CIPHERS, OPENSSL_INIT_ADD_ALL_DIGESTS,
};
use crate::runtime::obj::{OBJ_NAME_add, OBJ_NAME_get, OBJ_nid2ln, OBJ_nid2sn, OBJ_NAME_ALIAS};

/// `int EVP_add_cipher(const EVP_CIPHER *c)`.
///
/// Two insertions under the cipher's short and long name, and the answer is the second one's. A
/// NULL cipher is **0 without raising** — an adder is a registry write, and the authority's
/// callers (`openssl_add_all_ciphers_int`, Phase 13's) pass the result of a constructor that can
/// no longer be NULL in this profile.
///
/// `c` is the caller's object and is **borrowed, not copied**: `OBJ_NAME_add` stores the pointer,
/// and the authority says so in its own doc for the function the macro wraps. The cast to
/// `const char *` is the authority's, because the table's value slot is a string.
///
/// # Safety
/// `c` must be NULL or a live `EvpCipher` whose `nid` has both a short and a long name.
#[no_mangle]
pub unsafe extern "C" fn EVP_add_cipher(c: *const EvpCipher) -> c_int {
    if c.is_null() {
        return 0;
    }
    // SAFETY: `c` is live per the contract.
    let nid = unsafe { (*c).nid };
    // `OBJ_nid2sn` is safe in this crate: an integer in, a static string or NULL out.
    let short = OBJ_nid2sn(nid);
    // SAFETY: `OBJ_NAME_add` borrows both strings, and `short` is a static the object table owns.
    let r = unsafe { OBJ_NAME_add(short, OBJ_NAME_TYPE_CIPHER_METH, c.cast::<c_char>()) };
    if r == 0 {
        return 0;
    }
    let long = OBJ_nid2ln(nid);
    // SAFETY: as above.
    unsafe { OBJ_NAME_add(long, OBJ_NAME_TYPE_CIPHER_METH, c.cast::<c_char>()) }
}

/// `int EVP_add_digest(const EVP_MD *md)`.
///
/// Four insertions at most: the digest's own short and long name, and — when `pkey_type` names a
/// **different** object — that object's short and long name, as `EVP_NAME_ALIAS` entries whose
/// *data* is the digest's short name rather than the method. That last is the whole point of the
/// alias: `EVP_get_digestbyname("ssl3-md5")` has to answer the MD5 method, and the two
/// registrations say so without a second copy of the object.
///
/// **There is no NULL guard.** The authority reads `md->type` immediately, so a NULL is a fault
/// there; this crate refuses it instead
/// (`docs/SECURITY_DIVERGENCE_POLICY.md`, `D-NAMEMAP-DOALL-1`'s company) rather than importing a
/// crash — and the guard is stated here because a reader comparing the two bodies must not think
/// it was overlooked.
///
/// # Safety
/// `md` must be NULL or a live `EvpMd` whose `type_` has both a short and a long name.
#[no_mangle]
pub unsafe extern "C" fn EVP_add_digest(md: *const EvpMd) -> c_int {
    if md.is_null() {
        return 0;
    }
    // SAFETY: `md` is live per the contract.
    let type_ = unsafe { (*md).type_ };
    let name = OBJ_nid2sn(type_);
    // SAFETY: `OBJ_NAME_add` borrows both strings.
    let r = unsafe { OBJ_NAME_add(name, OBJ_NAME_TYPE_MD_METH, md.cast::<c_char>()) };
    if r == 0 {
        return 0;
    }
    let long = OBJ_nid2ln(type_);
    // SAFETY: as above.
    let r = unsafe { OBJ_NAME_add(long, OBJ_NAME_TYPE_MD_METH, md.cast::<c_char>()) };
    if r == 0 {
        return 0;
    }

    // SAFETY: `md` is live.
    let pkey_type = unsafe { (*md).pkey_type };
    if pkey_type != 0 && pkey_type != type_ {
        let pkey_short = OBJ_nid2sn(pkey_type);
        // SAFETY: `name` is the digest's own short name, which the table borrows as the alias's
        // target rather than as a method.
        let r = unsafe { OBJ_NAME_add(pkey_short, OBJ_NAME_TYPE_MD_METH | OBJ_NAME_ALIAS, name) };
        if r == 0 {
            return 0;
        }
        let pkey_long = OBJ_nid2ln(pkey_type);
        // SAFETY: as above.
        let r = unsafe { OBJ_NAME_add(pkey_long, OBJ_NAME_TYPE_MD_METH | OBJ_NAME_ALIAS, name) };
        return r;
    }
    r
}

// ---------------------------------------------------------------------------------------------
// The two lookups
//
// `crypto/evp/names.c`, and the shape is the same for both: try the legacy table, then the
// namemap, then *fetch* (which is what registers a name the namemap has never seen), then try the
// namemap again and walk every alias of the number that resolution produced. The fetch is wrapped
// in `ERR_set_mark`/`ERR_pop_to_mark` because it is a *probe*: a name that cannot be fetched is not
// an error the caller asked about, and the queue must be exactly as it was.
// ---------------------------------------------------------------------------------------------

/// `static void cipher_from_name(const char *name, void *data)`.
///
/// The namemap visitor. It answers **the first alias the table knows**, and it says so by refusing
/// to overwrite a non-NULL `*cipher` -- so the caller's slot is written at most once and the
/// remaining names of the number are still walked.
///
/// # Safety
/// `name` must be NUL-terminated; `data` must point at a live `*const EvpCipher`.
unsafe extern "C" fn cipher_from_name(name: *const c_char, data: *mut c_void) {
    let slot = data.cast::<*const EvpCipher>();
    if slot.is_null() {
        return;
    }
    // SAFETY: `slot` is live per the contract.
    if !unsafe { *slot }.is_null() {
        return;
    }
    // SAFETY: `name` is NUL-terminated per the contract.
    let found = unsafe { OBJ_NAME_get(name, OBJ_NAME_TYPE_CIPHER_METH) };
    // SAFETY: `slot` is live and writable.
    unsafe { *slot = found.cast::<EvpCipher>() };
}

/// `static void digest_from_name(const char *name, void *data)`.
///
/// # Safety
/// `name` must be NUL-terminated; `data` must point at a live `*const EvpMd`.
unsafe extern "C" fn digest_from_name(name: *const c_char, data: *mut c_void) {
    let slot = data.cast::<*const EvpMd>();
    if slot.is_null() {
        return;
    }
    // SAFETY: `slot` is live per the contract.
    if !unsafe { *slot }.is_null() {
        return;
    }
    // SAFETY: `name` is NUL-terminated per the contract.
    let found = unsafe { OBJ_NAME_get(name, OBJ_NAME_TYPE_MD_METH) };
    // SAFETY: `slot` is live and writable.
    unsafe { *slot = found.cast::<EvpMd>() };
}

/// `const EVP_CIPHER *evp_get_cipherbyname_ex(OSSL_LIB_CTX *libctx, const char *name)` — internal,
/// and the whole of the exported one-liner below it.
///
/// Three steps, and the third is a **loop** rather than a sequence because the fetch is what makes
/// the second step's answer non-zero: a name the namemap has never seen is fetched (and released
/// again -- the fetch is only there to register it), and then the namemap is asked once more. The
/// `do_retry` flag is what stops a second miss from fetching a second time.
///
/// # Safety
/// `libctx` NULL or live; `name` NULL or NUL-terminated.
pub(crate) unsafe fn evp_get_cipherbyname_ex(
    libctx: *mut c_void,
    name: *const c_char,
) -> *const EvpCipher {
    // The answer is ignored at the two call sites in `names.c`; the only thing it can report is a
    // refused initialisation option, which stops the lookup before it starts.
    if OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, ptr::null()) == 0 {
        return ptr::null();
    }

    // SAFETY: `name` is NULL or NUL-terminated per the contract.
    let cp = unsafe { OBJ_NAME_get(name, OBJ_NAME_TYPE_CIPHER_METH) }.cast::<EvpCipher>();
    if !cp.is_null() {
        return cp;
    }

    // SAFETY: `libctx` is NULL or live, and this answers the context's own namemap.
    let namemap = ossl_namemap_stored(libctx);
    let mut do_retry = 1;
    let mut slot = cp;
    loop {
        // SAFETY: `namemap` is live or NULL, which the callee refuses; `name` is NULL or
        // NUL-terminated.
        let id = unsafe { ossl_namemap_name2num(namemap, name) };
        if id == 0 {
            if do_retry == 0 {
                return ptr::null();
            }
            do_retry = 0;
            ERR_set_mark();
            // SAFETY: the arguments are forwarded under this function's contract, and the result
            // is released immediately -- the fetch exists to register the name.
            let fetched = unsafe { EVP_CIPHER_fetch(libctx, name, ptr::null()) };
            // SAFETY: `fetched` is NULL or live, which the callee accepts.
            unsafe { EVP_CIPHER_free(fetched) };
            ERR_pop_to_mark();
            continue;
        }
        /* `slot` is NULL on every path that reaches here: the early return above is the only other
         * assignment and it leaves the function. */
        // SAFETY: `namemap` is live, `id` is a number it knows, the visitor is this module's own,
        // and `slot` outlives the call.
        if unsafe {
            ossl_namemap_doall_names(
                namemap,
                id,
                Some(cipher_from_name),
                ptr::addr_of_mut!(slot).cast::<c_void>(),
            )
        } == 0
        {
            return ptr::null();
        }
        return slot;
    }
}

/// `const EVP_DIGEST *evp_get_digestbyname_ex(OSSL_LIB_CTX *libctx, const char *name)` — internal.
///
/// The digest half, differing only in the table's type and `OPENSSL_INIT_ADD_ALL_DIGESTS`. The
/// authority writes the two out; so does this, rather than parameterising them into one function
/// that would have to be told which of four things it is.
///
/// # Safety
/// `libctx` NULL or live; `name` NULL or NUL-terminated.
pub(crate) unsafe fn evp_get_digestbyname_ex(
    libctx: *mut c_void,
    name: *const c_char,
) -> *const EvpMd {
    if OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, ptr::null()) == 0 {
        return ptr::null();
    }

    // SAFETY: `name` is NULL or NUL-terminated per the contract.
    let dp = unsafe { OBJ_NAME_get(name, OBJ_NAME_TYPE_MD_METH) }.cast::<EvpMd>();
    if !dp.is_null() {
        return dp;
    }

    // SAFETY: `libctx` is NULL or live.
    let namemap = ossl_namemap_stored(libctx);
    let mut do_retry = 1;
    let mut slot = dp;
    loop {
        // SAFETY: `namemap` is live or NULL, which the callee refuses.
        let id = unsafe { ossl_namemap_name2num(namemap, name) };
        if id == 0 {
            if do_retry == 0 {
                return ptr::null();
            }
            do_retry = 0;
            ERR_set_mark();
            // SAFETY: the arguments are forwarded under this function's contract.
            let fetched = unsafe { EVP_MD_fetch(libctx, name, ptr::null()) };
            // SAFETY: `fetched` is NULL or live.
            unsafe { EVP_MD_free(fetched) };
            ERR_pop_to_mark();
            continue;
        }
        // SAFETY: `namemap` is live, `id` is a number it knows, the visitor is this module's own,
        // and `slot` outlives the call.
        if unsafe {
            ossl_namemap_doall_names(
                namemap,
                id,
                Some(digest_from_name),
                ptr::addr_of_mut!(slot).cast::<c_void>(),
            )
        } == 0
        {
            return ptr::null();
        }
        return slot;
    }
}

/// `const EVP_CIPHER *EVP_get_cipherbyname(const char *name)`.
///
/// The exported half, and it passes a **NULL `libctx`**: the lookup is the *default* context's,
/// which is why a caller cannot ask this function about a method registered in another context.
/// The `_ex` spelling is internal and has no export of its own.
///
/// # Safety
/// `name` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_get_cipherbyname(name: *const c_char) -> *const EvpCipher {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_get_cipherbyname_ex(ptr::null_mut(), name) }
}

/// `const EVP_MD *EVP_get_digestbyname(const char *name)`.
///
/// # Safety
/// `name` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_get_digestbyname(name: *const c_char) -> *const EvpMd {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_get_digestbyname_ex(ptr::null_mut(), name) }
}

// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::obj::{OBJ_NAME_get, OBJ_create};

    /// `OBJ_create` is how a test gets a NID that really has a short and a long name without
    /// depending on the object table's own contents.
    ///
    /// **All three strings must be fresh, and the long name is the one that catches a reader out:**
    /// `OBJ_create` refuses when *either* name is already taken, so a helper that varied only the
    /// short name answered `NID_undef` on its second call. That is the authority's rule too, and it
    /// is why this takes all three.
    fn a_fresh_nid(oid: &core::ffi::CStr, sn: &core::ffi::CStr, ln: &core::ffi::CStr) -> c_int {
        // SAFETY: the three strings are NUL-terminated and the object table takes copies.
        unsafe { OBJ_create(oid.as_ptr(), sn.as_ptr(), ln.as_ptr()) }
    }

    /// A cipher object with nothing in it but the one field an adder reads.
    fn a_bare_cipher(nid: c_int) -> EvpCipher {
        // SAFETY: the struct is read only through `nid` by the code under test, and every other
        // field's all-zero bit pattern is a valid value for it.
        let mut c = unsafe { core::mem::zeroed::<EvpCipher>() };
        c.nid = nid;
        c
    }

    /// A digest object with the two fields an adder reads.
    fn a_bare_digest(type_: c_int, pkey_type: c_int) -> EvpMd {
        // SAFETY: as above.
        let mut md = unsafe { core::mem::zeroed::<EvpMd>() };
        md.type_ = type_;
        md.pkey_type = pkey_type;
        md
    }

    /// A NULL cipher and a NULL digest are both refused, and neither raises: the adder is a
    /// registry write whose only precondition is the object it is handed.
    #[test]
    fn both_adders_guard_null_and_answer_zero() {
        // SAFETY: NULL is the documented refusal for both.
        unsafe {
            assert_eq!(EVP_add_cipher(core::ptr::null()), 0);
            assert_eq!(EVP_add_digest(core::ptr::null()), 0);
        }
    }

    /// The observable effect: after an add, the legacy table answers the method under both names.
    #[test]
    fn a_cipher_adder_registers_both_names() {
        let nid = a_fresh_nid(
            c"1.3.6.1.4.1.57264.9.1.1",
            c"openssl-rs test cipher sn",
            c"openssl-rs test cipher ln",
        );
        assert_ne!(nid, 0, "the test needed a fresh NID");
        let cipher = a_bare_cipher(nid);
        // SAFETY: `cipher` is this frame's own live object and stays alive for the registrations.
        assert_eq!(unsafe { EVP_add_cipher(core::ptr::addr_of!(cipher)) }, 1);
        // SAFETY: `nid` is live in the object table.
        let (short, long) = (OBJ_nid2sn(nid), OBJ_nid2ln(nid));
        // SAFETY: both are NUL-terminated strings owned by the object table.
        unsafe {
            assert_eq!(
                OBJ_NAME_get(short, OBJ_NAME_TYPE_CIPHER_METH),
                core::ptr::addr_of!(cipher).cast::<c_char>(),
                "the short name answers the method"
            );
            assert_eq!(
                OBJ_NAME_get(long, OBJ_NAME_TYPE_CIPHER_METH),
                core::ptr::addr_of!(cipher).cast::<c_char>(),
                "and so does the long name"
            );
        }
    }

    /// A second add under the same names **replaces** and answers 1 again: the adder is a write, not
    /// an insert-if-absent, and the answer is the last `OBJ_NAME_add`'s rather than a conjunction.
    #[test]
    fn a_repeated_add_replaces_and_still_answers_one() {
        let nid = a_fresh_nid(
            c"1.3.6.1.4.1.57264.9.1.2",
            c"openssl-rs test repeat sn",
            c"openssl-rs test repeat ln",
        );
        assert_ne!(nid, 0, "the test needed a fresh NID");
        let first = a_bare_cipher(nid);
        let second = a_bare_cipher(nid);
        // SAFETY: both are this frame's own live objects.
        unsafe {
            assert_eq!(EVP_add_cipher(core::ptr::addr_of!(first)), 1);
            assert_eq!(EVP_add_cipher(core::ptr::addr_of!(second)), 1);
        }
        // SAFETY: `nid` is live and its short name is a static string.
        let short = OBJ_nid2sn(nid);
        // SAFETY: `short` is NUL-terminated.
        unsafe {
            assert_eq!(
                OBJ_NAME_get(short, OBJ_NAME_TYPE_CIPHER_METH),
                core::ptr::addr_of!(second).cast::<c_char>(),
                "the second add is the one the table holds",
            );
        }
    }

    /// A digest whose `pkey_type` names a different object registers that object's short name as an
    /// **alias whose data is the digest's short name**, not a second copy of the method.
    #[test]
    fn a_digest_adder_registers_the_pkey_alias_by_name() {
        let type_ = a_fresh_nid(
            c"1.3.6.1.4.1.57264.9.1.3",
            c"openssl-rs test md sn",
            c"openssl-rs test md ln",
        );
        let pkey_type = a_fresh_nid(
            c"1.3.6.1.4.1.57264.9.1.4",
            c"openssl-rs test pkey sn",
            c"openssl-rs test pkey ln",
        );
        assert_ne!(type_, 0, "the test needed a fresh NID");
        assert_ne!(pkey_type, 0, "and a second one");
        let md = a_bare_digest(type_, pkey_type);
        // SAFETY: `md` is this frame's own live object.
        assert_eq!(unsafe { EVP_add_digest(core::ptr::addr_of!(md)) }, 1);
        let (short, pkey_short) = (OBJ_nid2sn(type_), OBJ_nid2sn(pkey_type));
        // SAFETY: `pkey_short` is a NUL-terminated string owned by the object table.
        unsafe {
            /* Asked for the alias **as an alias**, the table answers the string the adder stored
             * rather than the object it names. */
            assert_eq!(
                OBJ_NAME_get(pkey_short, OBJ_NAME_TYPE_MD_METH | OBJ_NAME_ALIAS),
                short,
                "the pkey name is an alias whose data is the digest's short name"
            );
            /* Asked for it plainly, `OBJ_NAME_get` follows the chain and answers the method --
             * which is what makes the alias useful to `EVP_get_digestbyname`. */
            assert_eq!(
                OBJ_NAME_get(pkey_short, OBJ_NAME_TYPE_MD_METH),
                core::ptr::addr_of!(md).cast::<c_char>(),
                "and the plain lookup follows it to the method"
            );
        }
    }

    /// A digest whose `pkey_type` is zero gets the two plain registrations and no alias.
    #[test]
    fn a_digest_with_no_pkey_type_registers_no_alias() {
        let type_ = a_fresh_nid(
            c"1.3.6.1.4.1.57264.9.1.5",
            c"openssl-rs test md nopkey sn",
            c"openssl-rs test md nopkey ln",
        );
        assert_ne!(type_, 0, "the test needed a fresh NID");
        let md = a_bare_digest(type_, 0);
        // SAFETY: `md` is this frame's own live object.
        assert_eq!(unsafe { EVP_add_digest(core::ptr::addr_of!(md)) }, 1);
        // SAFETY: `type_` is live and its short name is a static string.
        let short = OBJ_nid2sn(type_);
        // SAFETY: `short` is NUL-terminated.
        unsafe {
            assert_eq!(
                OBJ_NAME_get(short, OBJ_NAME_TYPE_MD_METH),
                core::ptr::addr_of!(md).cast::<c_char>()
            );
        }
    }
}
