//! Phase 8.1b — `crypto/md5/md5_sha1.c`: the concatenated MD5‖SHA-1 digest.
//!
//! `MD5-SHA1` is one `OSSL_OP_DIGEST` implementation whose output is MD5's sixteen bytes followed
//! by SHA-1's twenty, and whose context is the two contexts side by side — `prov/md5_sha1.h:29-32`
//! is literally `{ MD5_CTX md5; SHA_CTX sha1; }`. There is no exported low-level function for it:
//! `include/openssl/md5.h` and `sha.h` declare nothing, and `crypto/md5/md5_sha1.c`'s four entry
//! points are `ossl_`-prefixed and uninstalled. So this is provider work with nothing to export,
//! exactly as the plan's 8.1b row says of SM3 and SHA-3 (`docs/PHASE-8-SUBPHASES.md`, D197).
//!
//! The fourth entry point is `ossl_md5_sha1_ctrl`, the SSLv3 master-secret arm RFC 6101 §5.6.8
//! describes: it is `md5_sha1_prov.c`'s `set_ctx_params` body. It updates both halves with the
//! master secret and `pad_1`, finalises each, reinitialises, updates with the master secret and
//! `pad_2` plus the intermediates, and leaves the context so that a later `_final` answers the
//! SSLv3 value.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};
use core::ptr;

use crate::digest::md5::{MD5_Final, MD5_Init, MD5_Update, Md5Ctx};
use crate::digest::sha1::{SHA1_Final, SHA1_Init, SHA1_Update, ShaCtx};
use crate::runtime::mem::CleansedScratch;

/// `MD5_DIGEST_LENGTH` — `include/openssl/md5.h`.
pub(crate) const MD5_DIGEST_LENGTH: usize = 16;
/// `SHA_DIGEST_LENGTH` — `include/openssl/sha.h`.
pub(crate) const SHA_DIGEST_LENGTH: usize = 20;
/// `MD5_SHA1_DIGEST_LENGTH` — `prov/md5_sha1.h:21`.
pub(crate) const MD5_SHA1_DIGEST_LENGTH: usize = MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH;
/// `MD5_SHA1_CBLOCK` — `prov/md5_sha1.h:22`, which is `MD5_CBLOCK`.
pub(crate) const MD5_SHA1_CBLOCK: usize = 64;

/// `MD5_SHA1_CTX` — `prov/md5_sha1.h:29-32`. The two contexts side by side, in that order; the
/// layout is the authority's, so a provider context copied byte for byte stays valid.
#[repr(C)]
pub struct Md5Sha1Ctx {
    /// `MD5_CTX md5`.
    pub md5: Md5Ctx,
    /// `SHA_CTX sha1`.
    pub sha1: ShaCtx,
}

const _: () = {
    assert!(core::mem::size_of::<Md5Sha1Ctx>() == 92 + 96);
    assert!(core::mem::offset_of!(Md5Sha1Ctx, md5) == 0);
    assert!(core::mem::offset_of!(Md5Sha1Ctx, sha1) == 92);
};

/// `int ossl_md5_sha1_init(MD5_SHA1_CTX *mctx)` — `crypto/md5/md5_sha1.c:20-25`.
///
/// # Safety
/// `mctx` must be writable for `size_of::<Md5Sha1Ctx>()` bytes.
pub(crate) unsafe fn ossl_md5_sha1_init(mctx: *mut Md5Sha1Ctx) -> c_int {
    // SAFETY: `mctx` is writable per the caller's contract and the two fields are disjoint.
    unsafe {
        if MD5_Init(ptr::addr_of_mut!((*mctx).md5)) == 0 {
            return 0;
        }
        SHA1_Init(ptr::addr_of_mut!((*mctx).sha1))
    }
}

/// `int ossl_md5_sha1_update(MD5_SHA1_CTX *mctx, const void *data, size_t count)` —
/// `crypto/md5/md5_sha1.c:27-32`.
///
/// # Safety
/// `mctx` must be a live initialised context; `data` readable for `count` bytes.
pub(crate) unsafe fn ossl_md5_sha1_update(
    mctx: *mut Md5Sha1Ctx,
    data: *const c_void,
    count: usize,
) -> c_int {
    // SAFETY: as `ossl_md5_sha1_init`, and `data`/`count` are the caller's contract.
    unsafe {
        if MD5_Update(ptr::addr_of_mut!((*mctx).md5), data, count) == 0 {
            return 0;
        }
        SHA1_Update(ptr::addr_of_mut!((*mctx).sha1), data, count)
    }
}

/// `int ossl_md5_sha1_final(unsigned char *md, MD5_SHA1_CTX *mctx)` —
/// `crypto/md5/md5_sha1.c:34-39`.
///
/// # Safety
/// `mctx` must be a live initialised context; `md` writable for 36 bytes.
pub(crate) unsafe fn ossl_md5_sha1_final(md: *mut u8, mctx: *mut Md5Sha1Ctx) -> c_int {
    // SAFETY: `mctx` is live and `md` is writable for 36 bytes per the caller; the SHA-1 half
    // writes the sixteen bytes past MD5's own output.
    unsafe {
        if MD5_Final(md, ptr::addr_of_mut!((*mctx).md5)) == 0 {
            return 0;
        }
        SHA1_Final(md.add(MD5_DIGEST_LENGTH), ptr::addr_of_mut!((*mctx).sha1))
    }
}

/// `int ossl_md5_sha1_ctrl(MD5_SHA1_CTX *mctx, int cmd, int mslen, void *ms)` —
/// `crypto/md5/md5_sha1.c:41-108`. The SSLv3 master-secret arm.
///
/// # Safety
/// `mctx` must be a live context (a NULL one answers 0), and `ms` readable for `mslen` bytes when
/// `mslen` is 48.
pub(crate) unsafe fn ossl_md5_sha1_ctrl(
    mctx: *mut Md5Sha1Ctx,
    cmd: c_int,
    mslen: c_int,
    ms: *mut c_void,
) -> c_int {
    /// `EVP_CTRL_SSL3_MASTER_SECRET` — `include/openssl/evp.h`.
    const EVP_CTRL_SSL3_MASTER_SECRET: c_int = 0x1d;
    /// The authority's `unsigned char padtmp[48]`.
    const PAD_LENGTH: usize = 48;

    let mut padtmp = CleansedScratch::<PAD_LENGTH>::new();
    let mut md5tmp = CleansedScratch::<MD5_DIGEST_LENGTH>::new();
    let mut sha1tmp = CleansedScratch::<SHA_DIGEST_LENGTH>::new();

    if cmd != EVP_CTRL_SSL3_MASTER_SECRET {
        return -2;
    }
    if mctx.is_null() {
        return 0;
    }
    if mslen != 48 {
        return 0;
    }

    // SAFETY: `mctx` is live and `ms` is readable for `mslen == 48` bytes per the caller.
    if unsafe { ossl_md5_sha1_update(mctx, ms.cast_const(), mslen as usize) } <= 0 {
        return 0;
    }

    padtmp.fill(0x36);
    // SAFETY: the two contexts are live and `padtmp` is a live local of 48 bytes.
    unsafe {
        if MD5_Update(
            ptr::addr_of_mut!((*mctx).md5),
            padtmp.as_ptr().cast(),
            PAD_LENGTH,
        ) == 0
            || MD5_Final(md5tmp.as_mut_ptr(), ptr::addr_of_mut!((*mctx).md5)) == 0
            || SHA1_Update(ptr::addr_of_mut!((*mctx).sha1), padtmp.as_ptr().cast(), 40) == 0
            || SHA1_Final(sha1tmp.as_mut_ptr(), ptr::addr_of_mut!((*mctx).sha1)) == 0
        {
            return 0;
        }
    }

    // SAFETY: as above. A test may also refuse the result below, so that the early-failure
    // return after both intermediates were written can be reached and its cleanse observed;
    // the reinitialisation itself still happens exactly as the authority's does.
    let reinit = unsafe { ossl_md5_sha1_init(mctx) };
    #[cfg(test)]
    let init_fails = test_hooks::fail_init();
    #[cfg(not(test))]
    let init_fails = false;
    if init_fails || reinit == 0 {
        return 0;
    }
    // SAFETY: as the first update.
    if unsafe { ossl_md5_sha1_update(mctx, ms.cast_const(), mslen as usize) } <= 0 {
        return 0;
    }

    padtmp.fill(0x5c);
    // SAFETY: the two contexts are live and the three locals are live.
    unsafe {
        if MD5_Update(
            ptr::addr_of_mut!((*mctx).md5),
            padtmp.as_ptr().cast(),
            PAD_LENGTH,
        ) == 0
            || MD5_Update(
                ptr::addr_of_mut!((*mctx).md5),
                md5tmp.as_ptr().cast(),
                MD5_DIGEST_LENGTH,
            ) == 0
            || SHA1_Update(ptr::addr_of_mut!((*mctx).sha1), padtmp.as_ptr().cast(), 40) == 0
            || SHA1_Update(
                ptr::addr_of_mut!((*mctx).sha1),
                sha1tmp.as_ptr().cast(),
                SHA_DIGEST_LENGTH,
            ) == 0
        {
            return 0;
        }
    }

    // `md5tmp` and `sha1tmp` are secret-derived; `CleansedScratch::drop` wipes them (and the
    // pad temporary) on this success path and on every early return, exactly once each.
    1
}

#[cfg(test)]
mod test_hooks {
    use core::cell::Cell;

    thread_local! {
        /// Set by a test to make the ctrl's reinitialisation answer 0 exactly once.
        static FAIL_INIT: Cell<bool> = const { Cell::new(false) };
    }

    /// Consume a pending reinitialisation failure.
    pub(super) fn fail_init() -> bool {
        FAIL_INIT.with(|flag| flag.replace(false))
    }

    /// Ask the next `ossl_md5_sha1_ctrl` reinitialisation to fail.
    pub(crate) fn set_fail_init() {
        FAIL_INIT.with(|flag| flag.set(true));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Md5Sha1Ctx {
        Md5Sha1Ctx {
            md5: crate::digest::md5::Md5Ctx {
                a: 0,
                b: 0,
                c: 0,
                d: 0,
                nl: 0,
                nh: 0,
                data: [0; 16],
                num: 0,
            },
            sha1: crate::digest::sha1::ShaCtx {
                h0: 0,
                h1: 0,
                h2: 0,
                h3: 0,
                h4: 0,
                nl: 0,
                nh: 0,
                data: [0; 16],
                num: 0,
            },
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn digest(data: &[u8], split: Option<usize>) -> String {
        let mut c = ctx();
        let mut out = [0u8; MD5_SHA1_DIGEST_LENGTH];
        // SAFETY: every pointer below is a live local of this test.
        unsafe {
            assert_eq!(ossl_md5_sha1_init(&mut c), 1);
            match split {
                Some(at) => {
                    assert_eq!(ossl_md5_sha1_update(&mut c, data.as_ptr().cast(), at), 1);
                    assert_eq!(
                        ossl_md5_sha1_update(&mut c, data.as_ptr().add(at).cast(), data.len() - at),
                        1
                    );
                }
                None => {
                    assert_eq!(
                        ossl_md5_sha1_update(&mut c, data.as_ptr().cast(), data.len()),
                        1
                    )
                }
            }
            assert_eq!(ossl_md5_sha1_final(out.as_mut_ptr(), &mut c), 1);
        }
        hex(&out)
    }

    /// The concatenation is MD5's own published answer followed by SHA-1's.
    #[test]
    fn the_digest_is_md5_then_sha1() {
        assert_eq!(
            digest(b"", None),
            "d41d8cd98f00b204e9800998ecf8427eda39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            digest(b"abc", None),
            "900150983cd24fb0d6963f7d28e17f72a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn a_split_update_answers_the_same_as_one_call() {
        let mut data = [0u8; 200];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i * 7 + 3) as u8;
        }
        for len in [0usize, 1, 55, 56, 63, 64, 65, 128, 200] {
            let msg = &data[..len];
            assert_eq!(digest(msg, None), digest(msg, Some(len / 2)), "len {len}");
        }
    }

    /// The ctrl's three secret temporaries are cleansed on the early-failure return that follows
    /// the two inner finalisations: the reinitialisation is refused, so `padtmp`, `md5tmp` and
    /// `sha1tmp` still hold master-secret-derived state when the function returns. The
    /// observation is the test-only hook in `CleansedScratch::drop`, which reads the owner's
    /// live storage, never freed stack.
    #[test]
    fn md5_sha1_ctrl_cleanses_on_early_failure() {
        let mut c = ctx();
        let secret = [0xa5u8; 48];
        crate::runtime::mem::cleanse_hooks::reset();
        test_hooks::set_fail_init();
        // SAFETY: every pointer is a live local and `secret` is 48 bytes.
        let ret =
            unsafe { ossl_md5_sha1_ctrl(&mut c, 0x1d, 48, secret.as_ptr().cast_mut().cast()) };
        assert_eq!(ret, 0, "the injected reinitialisation failure answers 0");

        let events = crate::runtime::mem::cleanse_hooks::events();
        assert_eq!(
            events.len(),
            3,
            "all three temporaries are wiped: {events:?}"
        );
        let pad = events
            .iter()
            .find(|e| e.len == 48)
            .map(|e| e.nonzero_before);
        let md5 = events
            .iter()
            .find(|e| e.len == 16)
            .map(|e| e.nonzero_before);
        let sha1 = events
            .iter()
            .find(|e| e.len == 20)
            .map(|e| e.nonzero_before);
        assert_eq!(pad, Some(48), "the 0x36 padding was present: {events:?}");
        assert!(
            md5.is_some_and(|nonzero| nonzero > 0),
            "the MD5 intermediate was secret-derived: {events:?}"
        );
        assert!(
            sha1.is_some_and(|nonzero| nonzero > 0),
            "the SHA-1 intermediate was secret-derived: {events:?}"
        );
        assert!(events.iter().all(|e| e.zero_after), "{events:?}");
    }

    /// The success path cleanses all three temporaries exactly once as well; the wipe is the
    /// owner's `Drop`, not a separate call on one arm.
    #[test]
    fn md5_sha1_ctrl_cleanses_on_success() {
        let mut c = ctx();
        let secret = [0xa5u8; 48];
        crate::runtime::mem::cleanse_hooks::reset();
        // SAFETY: every pointer is a live local and `secret` is 48 bytes.
        let ret =
            unsafe { ossl_md5_sha1_ctrl(&mut c, 0x1d, 48, secret.as_ptr().cast_mut().cast()) };
        assert_eq!(ret, 1);

        let events = crate::runtime::mem::cleanse_hooks::events();
        assert_eq!(events.len(), 3, "wiped exactly once each: {events:?}");
        assert!(
            events.iter().all(|e| e.zero_after),
            "every temporary reads zero: {events:?}"
        );
        assert!(
            events.iter().filter(|e| e.nonzero_before > 0).count() == 3,
            "all three held state before the wipe: {events:?}"
        );
    }
}
