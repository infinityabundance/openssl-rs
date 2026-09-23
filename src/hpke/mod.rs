//! Phase 7.6 — `crypto/hpke/hpke.c`: the RFC 9180 HPKE `OSSL_HPKE_*` surface.
//!
//! Twenty exports, a KEM-encapsulation layer that sits over `EVP_PKEY`'s KEM operations, `EVP_KDF`
//! (HKDF) and `EVP_CIPHER`'s AEAD mode. It is the third of this subphase's header surfaces and the
//! one the plan's row expects to be partly blocked.
//!
//! ## The AEAD premise in the brief is false as measured, and the measurement is here
//!
//! The row's brief says the layer is "over `EVP_KEM`, `EVP_KDF` and, importantly, `EVP_AEAD`
//! (`crypto/evp/evp_aead.c`)". **There is no `EVP_AEAD` object in this authority at all**: a
//! search over the pinned source for `EVP_AEAD_CTX`, `EVP_AEAD` and `evp_aead` returns nothing,
//! there is no `crypto/evp/evp_aead.c` in the manifest, and `include/crypto/evp.h` does not
//! declare one. What `hpke_aead_enc`/`hpke_aead_dec` (`crypto/hpke/hpke.c:219`, `:141`) use is an
//! `EVP_CIPHER` in AEAD mode — `EVP_EncryptInit_ex`/`EVP_DecryptInit_ex` over `ctx->aead_ciph`,
//! with `EVP_CTRL_AEAD_SET_IVLEN`, `EVP_CTRL_AEAD_GET_TAG` and `EVP_CTRL_AEAD_SET_TAG` — and
//! `ctx->aead_ciph` is `EVP_CIPHER_fetch(libctx, aead_info->name, propq)` (`hpke.c:841`). So the
//! dependency the brief names does not exist, and the surface that *does* exist is this stratum's
//! own 7.3b/7.3c work. No export is withheld on it.
//!
//! ## `hpke_util.c` is not a ledger unit, and its internals land here
//!
//! `crypto/hpke/hpke.c`'s helpers are `crypto/hpke/hpke_util.c`'s, declared in the **uninstalled**
//! `include/internal/hpke_util.h`, so the atlas does not census them as obligations and the
//! ledger has no module for them. They are transcribed as `pub(crate)` internals beside the
//! exports they serve, with one deliberate substitution and one omission:
//!
//!   * `ossl_hpke_labeled_extract`/`_expand` build a labelled byte string through `WPACKET`
//!     (`include/internal/packet.h`), which this crate does not have. The `WPACKET_*` calls there
//!     are an exactly-sized concatenation and nothing else — the buffer length is computed as the
//!     exact sum of the pieces, so `WPACKET_finish` cannot fail and the
//!     `PROV_R_OUTPUT_BUFFER_TOO_SMALL` arm at `hpke_util.c:329`/`:380` is **unreachable**. The
//!     concatenation is written directly, and the unreachable arm is named rather than stubbed.
//!   * `ossl_HPKE_KEM_INFO_find_random`, `ossl_HPKE_KDF_INFO_find_random` and
//!     `ossl_HPKE_AEAD_INFO_find_random` are omitted, together with `hpke_random_suite`, because
//!     their only caller is `OSSL_HPKE_get_grease_value`, which is itself withheld on
//!     `RAND_bytes_ex` (Phase 9, `hpke.c:1433`). They call `ossl_rand_uniform_uint32`
//!     (`crypto/rand/rand_lib.c`, Phase 9). `ossl_HPKE_KEM_INFO_find_curve` is omitted for the
//!     same reason in the other direction: nothing in `hpke.c` calls it.
//!
//! ## What is withheld, and why
//!
//! **`OSSL_HPKE_get_grease_value`** (`crypto/hpke/hpke.c:1377`) is the one export that does not
//! land. It calls `RAND_bytes_ex` (`hpke.c:1433`) to fill the GREASE ciphertext, and
//! `ossl_rand_uniform_uint32` (`hpke_util.c:198`, `:220`, `:243`) to pick a random suite. Both are
//! `crypto/rand/`'s and Phase 9's. There is no partial answer: the whole observable is whether
//! that random fill succeeds. It has a `forensics/prerequisites.json` row and a
//! `NOT_MEASURED_…` line in `RT-HPKE`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EvpCipher};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_DecryptFinal_ex,
    EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptInit_ex,
    EVP_EncryptUpdate,
};
use crate::evp::kdf::{
    EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_CTX_set_params, EVP_KDF_derive, EVP_KDF_fetch,
    EVP_KDF_free, EvpKdf, EvpKdfCtx, OSSL_KDF_PARAM_KEY,
};
use crate::evp::kem::{
    EVP_PKEY_auth_decapsulate_init, EVP_PKEY_auth_encapsulate_init, EVP_PKEY_decapsulate,
    EVP_PKEY_decapsulate_init, EVP_PKEY_encapsulate, EVP_PKEY_encapsulate_init,
};
use crate::evp::pkey::{
    EVP_PKEY_dup, EVP_PKEY_free, EVP_PKEY_get_octet_string_param, EVP_PKEY_new_raw_public_key_ex,
    EVP_PKEY_set1_encoded_public_key, EvpPkey,
};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_name, EVP_PKEY_CTX_new_from_pkey,
    EVP_PKEY_CTX_set_params, EvpPkeyCtx,
};
use crate::evp::pmeth_gn::{
    EVP_PKEY_generate, EVP_PKEY_keygen_init, EVP_PKEY_paramgen, EVP_PKEY_paramgen_init,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_utf8_string, OsslParam,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};

// ---------------------------------------------------------------------------------------------
// The constants — `include/openssl/hpke.h`, `include/internal/hpke_util.h` and `core_names.h`.
// ---------------------------------------------------------------------------------------------

/// `OSSL_HPKE_MODE_BASE`/`_PSK`/`_AUTH`/`_PSKAUTH` — `hpke.h:18`.
const OSSL_HPKE_MODE_BASE: c_int = 0;
const OSSL_HPKE_MODE_PSK: c_int = 1;
const OSSL_HPKE_MODE_AUTH: c_int = 2;
const OSSL_HPKE_MODE_PSKAUTH: c_int = 3;

/// `OSSL_HPKE_ROLE_SENDER`/`_RECEIVER` — `hpke.h:73`.
const OSSL_HPKE_ROLE_SENDER: c_int = 0;
const OSSL_HPKE_ROLE_RECEIVER: c_int = 1;

/// `OSSL_HPKE_MAX_PARMLEN`, `_MIN_PSKLEN`, `_MAX_INFOLEN` — `hpke.h:28`.
const OSSL_HPKE_MAX_PARMLEN: usize = 66;
const OSSL_HPKE_MIN_PSKLEN: usize = 32;
const OSSL_HPKE_MAX_INFOLEN: usize = 1024;

/// `OSSL_HPKE_KEM_ID_*` — `hpke.h:37`.
const OSSL_HPKE_KEM_ID_RESERVED: u16 = 0x0000;
const OSSL_HPKE_KEM_ID_P256: u16 = 0x0010;
const OSSL_HPKE_KEM_ID_P384: u16 = 0x0011;
const OSSL_HPKE_KEM_ID_P521: u16 = 0x0012;
const OSSL_HPKE_KEM_ID_X25519: u16 = 0x0020;
const OSSL_HPKE_KEM_ID_X448: u16 = 0x0021;

/// `OSSL_HPKE_KDF_ID_*` — `hpke.h:44`.
const OSSL_HPKE_KDF_ID_HKDF_SHA256: u16 = 0x0001;
const OSSL_HPKE_KDF_ID_HKDF_SHA384: u16 = 0x0002;
const OSSL_HPKE_KDF_ID_HKDF_SHA512: u16 = 0x0003;

/// `OSSL_HPKE_AEAD_ID_*` — `hpke.h:49`.
const OSSL_HPKE_AEAD_ID_AES_GCM_128: u16 = 0x0001;
const OSSL_HPKE_AEAD_ID_AES_GCM_256: u16 = 0x0002;
const OSSL_HPKE_AEAD_ID_CHACHA_POLY1305: u16 = 0x0003;
const OSSL_HPKE_AEAD_ID_EXPORTONLY: u16 = 0xFFFF;

/// `OSSL_HPKE_MAX_NONCELEN` — `include/internal/hpke_util.h:24`.
const OSSL_HPKE_MAX_NONCELEN: usize = 12;

/// `OSSL_HPKE_MAXSIZE` — `hpke.c:25`. The default buffer size for the key-schedule arrays.
const OSSL_HPKE_MAXSIZE: usize = 512;

/// `OSSL_HPKE_MAX_SUITESTR` — `hpke_util.c:43`.
const OSSL_HPKE_MAX_SUITESTR: usize = 38;

/// `OSSL_HPKE_STR_DELIMCHAR` — `hpke_util.c:29`.
const OSSL_HPKE_STR_DELIMCHAR: c_char = b',' as c_char;

/// `EVP_MAX_AEAD_TAG_LENGTH` — `include/openssl/evp.h:38`.
const EVP_MAX_AEAD_TAG_LENGTH: usize = 16;

/// `X25519_KEYLEN`/`X448_KEYLEN` — `include/crypto/ecx.h:26`.
const X25519_KEYLEN: usize = 32;
const X448_KEYLEN: usize = 56;

/// `SHA256_DIGEST_LENGTH`/`SHA384`/`SHA512` — `include/openssl/sha.h:86`.
const SHA256_DIGEST_LENGTH: usize = 32;
const SHA384_DIGEST_LENGTH: usize = 48;
const SHA512_DIGEST_LENGTH: usize = 64;

/// `EVP_CTRL_AEAD_*` — `include/openssl/evp.h:388`.
const EVP_CTRL_AEAD_SET_IVLEN: c_int = 0x9;
const EVP_CTRL_AEAD_GET_TAG: c_int = 0x10;
const EVP_CTRL_AEAD_SET_TAG: c_int = 0x11;

/// `EVP_KDF_HKDF_MODE_EXTRACT_ONLY`/`_EXPAND_ONLY` — `include/openssl/kdf.h:67`.
const EVP_KDF_HKDF_MODE_EXTRACT_ONLY: c_int = 1;
const EVP_KDF_HKDF_MODE_EXPAND_ONLY: c_int = 2;

/// `OSSL_KDF_PARAM_MODE`/`_INFO`/`_SALT`/`_DIGEST`/`_PROPERTIES` — `core_names.h:281`.
const OSSL_KDF_PARAM_MODE: *const c_char = c"mode".as_ptr();
const OSSL_KDF_PARAM_INFO: *const c_char = c"info".as_ptr();
const OSSL_KDF_PARAM_SALT: *const c_char = c"salt".as_ptr();
const OSSL_KDF_PARAM_DIGEST: *const c_char = c"digest".as_ptr();
const OSSL_KDF_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();

/// `OSSL_KEM_PARAM_OPERATION` and its `DHKEM` value — `core_names.h:326`, `:118`.
const OSSL_KEM_PARAM_OPERATION: *const c_char = c"operation".as_ptr();
const OSSL_KEM_PARAM_OPERATION_DHKEM: *const c_char = c"DHKEM".as_ptr();
/// `OSSL_KEM_PARAM_IKME` — `core_names.h:325`.
const OSSL_KEM_PARAM_IKME: *const c_char = c"ikme".as_ptr();

/// `OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY` — `core_names.h:398`.
const OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY: *const c_char = c"encoded-pub-key".as_ptr();
/// `OSSL_PKEY_PARAM_GROUP_NAME` — `core_names.h:420`.
const OSSL_PKEY_PARAM_GROUP_NAME: *const c_char = c"group".as_ptr();
/// `OSSL_PKEY_PARAM_DHKEM_IKM` — `core_names.h:371`.
const OSSL_PKEY_PARAM_DHKEM_IKM: *const c_char = c"dhkem-ikm".as_ptr();

/// The RFC 9180 labels — `hpke.c:29`..`:43`. They are spelled in hex in the authority "for EBCDIC
/// compatibility"; the bytes are the ASCII strings named in each comment.
const LABEL_HPKEV1: &[u8] = b"HPKE-v1";
const SEC51LABEL: &[u8] = b"HPKE";
const PSKIDHASH_LABEL: &[u8] = b"psk_id_hash";
const INFOHASH_LABEL: &[u8] = b"info_hash";
const NONCE_LABEL: &[u8] = b"base_nonce";
const EXP_LABEL: &[u8] = b"exp";
const EXP_SEC_LABEL: &[u8] = b"sec";
const KEY_LABEL: &[u8] = b"key";
const SECRET_LABEL: &[u8] = b"secret";

/// `crypto/hpke/hpke.c` and `crypto/hpke/hpke_util.c` — the two coordinates the crate's
/// allocations are attributed to. The raises carry their own sites.
const FILE_HPKE: *const c_char = c"../../src/openssl-3.6.4/crypto/hpke/hpke.c".as_ptr();
const FILE_HPKE_UTIL: *const c_char = c"../../src/openssl-3.6.4/crypto/hpke/hpke_util.c".as_ptr();

// ---------------------------------------------------------------------------------------------
// The information tables — `hpke_util.c:63`, `:88`, `:104`.
// ---------------------------------------------------------------------------------------------

/// `OSSL_HPKE_KEM_INFO` — `include/internal/hpke_util.h:31`.
///
/// `mdname`, `nsecret`, `npk` and `bitmask` are declared because they are the authority's fields
/// and the table is the authority's, but `crypto/hpke/hpke.c` itself reads only `keytype`,
/// `groupname`, `Nenc` and `Nsk`; the other four are read by `providers/`'s HPKE KEM, Phase 13.
/// They carry a `dead_code` allowance naming that owner rather than being dropped, because a
/// table with four of its nine columns missing is no longer a transcription of the authority's.
#[allow(dead_code)]
pub(crate) struct HpkeKemInfo {
    /// `uint16_t kem_id`.
    pub(crate) kem_id: u16,
    /// `const char *keytype` — `"EC"`/`"X25519"`/`"X448"`, the keymgmt name to fetch.
    pub(crate) keytype: &'static core::ffi::CStr,
    /// `const char *groupname` — the EC group for a NIST curve, `NULL` otherwise.
    pub(crate) groupname: Option<&'static core::ffi::CStr>,
    /// `const char *mdname` — the HKDF digest name.
    pub(crate) mdname: &'static core::ffi::CStr,
    /// `size_t Nsecret`.
    pub(crate) nsecret: usize,
    /// `size_t Nenc`.
    pub(crate) nenc: usize,
    /// `size_t Npk`.
    pub(crate) npk: usize,
    /// `size_t Nsk`.
    pub(crate) nsk: usize,
    /// `uint8_t bitmask`.
    pub(crate) bitmask: u8,
}

/// `OSSL_HPKE_KDF_INFO` — `include/internal/hpke_util.h:46`.
pub(crate) struct HpkeKdfInfo {
    /// `uint16_t kdf_id`.
    pub(crate) kdf_id: u16,
    /// `const char *mdname`.
    pub(crate) mdname: &'static core::ffi::CStr,
    /// `size_t Nh`.
    pub(crate) nh: usize,
}

/// `OSSL_HPKE_AEAD_INFO` — `include/internal/hpke_util.h:55`.
pub(crate) struct HpkeAeadInfo {
    /// `uint16_t aead_id`.
    pub(crate) aead_id: u16,
    /// `const char *name` — the cipher name, `NULL` for the export-only pseudo-AEAD.
    pub(crate) name: Option<&'static core::ffi::CStr>,
    /// `size_t taglen`.
    pub(crate) taglen: usize,
    /// `size_t Nk`.
    pub(crate) nk: usize,
    /// `size_t Nn`.
    pub(crate) nn: usize,
}

/// `static const OSSL_HPKE_KEM_INFO hpke_kem_tab[]` — `hpke_util.c:63`. The `OPENSSL_NO_EC` and
/// `OPENSSL_NO_ECX` guards are not set on this profile, so all five entries are compiled.
static KEM_TAB: [HpkeKemInfo; 5] = [
    HpkeKemInfo {
        kem_id: OSSL_HPKE_KEM_ID_P256,
        keytype: c"EC",
        groupname: Some(c"P-256"),
        mdname: c"sha256",
        nsecret: SHA256_DIGEST_LENGTH,
        nenc: 65,
        npk: 65,
        nsk: 32,
        bitmask: 0xFF,
    },
    HpkeKemInfo {
        kem_id: OSSL_HPKE_KEM_ID_P384,
        keytype: c"EC",
        groupname: Some(c"P-384"),
        mdname: c"sha384",
        nsecret: SHA384_DIGEST_LENGTH,
        nenc: 97,
        npk: 97,
        nsk: 48,
        bitmask: 0xFF,
    },
    HpkeKemInfo {
        kem_id: OSSL_HPKE_KEM_ID_P521,
        keytype: c"EC",
        groupname: Some(c"P-521"),
        mdname: c"sha512",
        nsecret: SHA512_DIGEST_LENGTH,
        nenc: 133,
        npk: 133,
        nsk: 66,
        bitmask: 0x01,
    },
    HpkeKemInfo {
        kem_id: OSSL_HPKE_KEM_ID_X25519,
        keytype: c"X25519",
        groupname: None,
        mdname: c"sha256",
        nsecret: SHA256_DIGEST_LENGTH,
        nenc: X25519_KEYLEN,
        npk: X25519_KEYLEN,
        nsk: X25519_KEYLEN,
        bitmask: 0x00,
    },
    HpkeKemInfo {
        kem_id: OSSL_HPKE_KEM_ID_X448,
        keytype: c"X448",
        groupname: None,
        mdname: c"sha512",
        nsecret: SHA512_DIGEST_LENGTH,
        nenc: X448_KEYLEN,
        npk: X448_KEYLEN,
        nsk: X448_KEYLEN,
        bitmask: 0x00,
    },
];

/// `static const OSSL_HPKE_AEAD_INFO hpke_aead_tab[]` — `hpke_util.c:88`.
static AEAD_TAB: [HpkeAeadInfo; 4] = [
    HpkeAeadInfo {
        aead_id: OSSL_HPKE_AEAD_ID_AES_GCM_128,
        name: Some(c"aes-128-gcm"),
        taglen: 16,
        nk: 16,
        nn: OSSL_HPKE_MAX_NONCELEN,
    },
    HpkeAeadInfo {
        aead_id: OSSL_HPKE_AEAD_ID_AES_GCM_256,
        name: Some(c"aes-256-gcm"),
        taglen: 16,
        nk: 32,
        nn: OSSL_HPKE_MAX_NONCELEN,
    },
    HpkeAeadInfo {
        aead_id: OSSL_HPKE_AEAD_ID_CHACHA_POLY1305,
        name: Some(c"chacha20-poly1305"),
        taglen: 16,
        nk: 32,
        nn: OSSL_HPKE_MAX_NONCELEN,
    },
    HpkeAeadInfo {
        aead_id: OSSL_HPKE_AEAD_ID_EXPORTONLY,
        name: None,
        taglen: 0,
        nk: 0,
        nn: 0,
    },
];

/// `static const OSSL_HPKE_KDF_INFO hpke_kdf_tab[]` — `hpke_util.c:104`.
static KDF_TAB: [HpkeKdfInfo; 3] = [
    HpkeKdfInfo {
        kdf_id: OSSL_HPKE_KDF_ID_HKDF_SHA256,
        mdname: c"sha256",
        nh: SHA256_DIGEST_LENGTH,
    },
    HpkeKdfInfo {
        kdf_id: OSSL_HPKE_KDF_ID_HKDF_SHA384,
        mdname: c"sha384",
        nh: SHA384_DIGEST_LENGTH,
    },
    HpkeKdfInfo {
        kdf_id: OSSL_HPKE_KDF_ID_HKDF_SHA512,
        mdname: c"sha512",
        nh: SHA512_DIGEST_LENGTH,
    },
];

/// The three synonym tables — `hpke_util.c:122`, `:136`, `:144`. The second and third names of
/// the first entry are the same string in the authority (`"0x10","0x10","16"`), which is kept.
static KEMSTRTAB: [(u16, [&str; 4]); 5] = [
    (OSSL_HPKE_KEM_ID_P256, ["P-256", "0x10", "0x10", "16"]),
    (OSSL_HPKE_KEM_ID_P384, ["P-384", "0x11", "0x11", "17"]),
    (OSSL_HPKE_KEM_ID_P521, ["P-521", "0x12", "0x12", "18"]),
    (OSSL_HPKE_KEM_ID_X25519, ["X25519", "0x20", "0x20", "32"]),
    (OSSL_HPKE_KEM_ID_X448, ["X448", "0x21", "0x21", "33"]),
];
static KDFSTRTAB: [(u16, [&str; 4]); 3] = [
    (
        OSSL_HPKE_KDF_ID_HKDF_SHA256,
        ["hkdf-sha256", "0x1", "0x01", "1"],
    ),
    (
        OSSL_HPKE_KDF_ID_HKDF_SHA384,
        ["hkdf-sha384", "0x2", "0x02", "2"],
    ),
    (
        OSSL_HPKE_KDF_ID_HKDF_SHA512,
        ["hkdf-sha512", "0x3", "0x03", "3"],
    ),
];
static AEADSTRTAB: [(u16, [&str; 4]); 4] = [
    (
        OSSL_HPKE_AEAD_ID_AES_GCM_128,
        ["aes-128-gcm", "0x1", "0x01", "1"],
    ),
    (
        OSSL_HPKE_AEAD_ID_AES_GCM_256,
        ["aes-256-gcm", "0x2", "0x02", "2"],
    ),
    (
        OSSL_HPKE_AEAD_ID_CHACHA_POLY1305,
        ["chacha20-poly1305", "0x3", "0x03", "3"],
    ),
    (
        OSSL_HPKE_AEAD_ID_EXPORTONLY,
        ["exporter", "ff", "0xff", "255"],
    ),
];

// ---------------------------------------------------------------------------------------------
// The `hpke_util.c` internals.
// ---------------------------------------------------------------------------------------------

/// `const OSSL_HPKE_KEM_INFO *ossl_HPKE_KEM_INFO_find_id(uint16_t kemid)` —
/// `hpke_util.c:172`.
///
/// The `RESERVED` code point is a raise of its own ("this check can happen if we're in a no-ec
/// build"), which is why it is not simply a miss.
fn kem_info_find_id(kemid: u16) -> Option<&'static HpkeKemInfo> {
    if kemid == OSSL_HPKE_KEM_ID_RESERVED {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_UTIL_181) };
        return None;
    }
    for info in KEM_TAB.iter() {
        if info.kem_id == kemid {
            return Some(info);
        }
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::HPKE_UTIL_188) };
    None
}

/// `const OSSL_HPKE_KEM_INFO *ossl_HPKE_KEM_INFO_find_curve(const char *curve)` —
/// `hpke_util.c:156`.
///
/// The authority's `OSSL_NELEM` walk over `hpke_kem_tab[]`, comparing the argument against each
/// row's `groupname`, or against its `keytype` where `groupname` is `NULL`. Nothing in
/// `crypto/hpke/hpke.c` calls it -- hence the omission the module documentation records -- and the
/// **keys'** KEM units are its first callers: `providers/implementations/kem/ecx_kem.c`'s
/// `get_kem_info` (`:80`) passes `SN_X25519`/`SN_X448` and needs the walk to resolve them to a
/// suite. The miss raises, which is why the match is not a quiet `None`.
///
/// # Safety
/// `curve` is NUL-terminated.
#[allow(non_snake_case)] // the authority's own symbol name
pub(crate) unsafe extern "C" fn ossl_HPKE_KEM_INFO_find_curve(
    curve: *const c_char,
) -> *const HpkeKemInfo {
    for info in KEM_TAB.iter() {
        let group = match info.groupname {
            Some(g) => g.as_ptr(),
            None => info.keytype.as_ptr(),
        };
        // SAFETY: `curve` is NUL-terminated per the contract and `group` is a `'static` literal.
        if unsafe { crate::runtime::str::OPENSSL_strcasecmp(curve, group) } == 0 {
            return info;
        }
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::HPKE_UTIL_168) };
    ptr::null()
}

/// `const OSSL_HPKE_KDF_INFO *ossl_HPKE_KDF_INFO_find_id(uint16_t kdfid)` —
/// `hpke_util.c:202`.
fn kdf_info_find_id(kdfid: u16) -> Option<&'static HpkeKdfInfo> {
    for info in KDF_TAB.iter() {
        if info.kdf_id == kdfid {
            return Some(info);
        }
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::HPKE_UTIL_210) };
    None
}

/// `const OSSL_HPKE_AEAD_INFO *ossl_HPKE_AEAD_INFO_find_id(uint16_t aeadid)` —
/// `hpke_util.c:224`.
fn aead_info_find_id(aeadid: u16) -> Option<&'static HpkeAeadInfo> {
    for info in AEAD_TAB.iter() {
        if info.aead_id == aeadid {
            return Some(info);
        }
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::HPKE_UTIL_232) };
    None
}

/// `static int kdf_derive(EVP_KDF_CTX *kctx, unsigned char *out, size_t outlen, int mode,
///     const unsigned char *salt, size_t saltlen, const unsigned char *ikm, size_t ikmlen,
///     const unsigned char *info, size_t infolen)` — `hpke_util.c:247`.
///
/// The one refusal is `EVP_KDF_derive`'s own `> 0` test, and it raises
/// `PROV_R_FAILED_DURING_DERIVATION` — a **provider** library code, because the function lives in
/// `providers/`'s world in the authority even though it is called from `crypto/`.
///
/// # Safety
/// `kctx` must be live; `out` writable for `outlen`; each of `salt`/`ikm`/`info` NULL or readable
/// for its length.
#[allow(clippy::too_many_arguments)]
unsafe fn kdf_derive(
    kctx: *mut EvpKdfCtx,
    out: *mut c_uchar,
    outlen: usize,
    mode: c_int,
    salt: *const c_uchar,
    saltlen: usize,
    ikm: *const c_uchar,
    ikmlen: usize,
    info: *const c_uchar,
    infolen: usize,
) -> c_int {
    let mut mode_v = mode;
    let mut params: [OsslParam; 5] = [OSSL_PARAM_construct_end(); 5];
    let mut p = 0usize;
    // SAFETY: each constructor writes one entry, the array has five, and `mode_v` outlives the
    // call to `EVP_KDF_derive` below.
    unsafe {
        params[p] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mut mode_v);
        p += 1;
        if !salt.is_null() {
            params[p] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SALT,
                salt.cast_mut().cast::<c_void>(),
                saltlen,
            );
            p += 1;
        }
        if !ikm.is_null() {
            params[p] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_KEY,
                ikm.cast_mut().cast::<c_void>(),
                ikmlen,
            );
            p += 1;
        }
        if !info.is_null() {
            params[p] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_INFO,
                info.cast_mut().cast::<c_void>(),
                infolen,
            );
            p += 1;
        }
        params[p] = OSSL_PARAM_construct_end();
    }
    // SAFETY: `kctx` is live per the contract and `params` is terminated.
    let ret = unsafe { EVP_KDF_derive(kctx, out, outlen, params.as_ptr()) } > 0;
    if !ret {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_UTIL_269) };
    }
    c_int::from(ret)
}

/// `int ossl_hpke_kdf_extract(...)` — `hpke_util.c:273`.
///
/// # Safety
/// As `kdf_derive`.
#[allow(clippy::too_many_arguments)]
unsafe fn hpke_kdf_extract(
    kctx: *mut EvpKdfCtx,
    prk: *mut c_uchar,
    prklen: usize,
    salt: *const c_uchar,
    saltlen: usize,
    ikm: *const c_uchar,
    ikmlen: usize,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe {
        kdf_derive(
            kctx,
            prk,
            prklen,
            EVP_KDF_HKDF_MODE_EXTRACT_ONLY,
            salt,
            saltlen,
            ikm,
            ikmlen,
            ptr::null(),
            0,
        )
    }
}

/// `int ossl_hpke_kdf_expand(...)` — `hpke_util.c:283`.
///
/// # Safety
/// As `kdf_derive`.
#[allow(clippy::too_many_arguments)]
unsafe fn hpke_kdf_expand(
    kctx: *mut EvpKdfCtx,
    okm: *mut c_uchar,
    okmlen: usize,
    prk: *const c_uchar,
    prklen: usize,
    info: *const c_uchar,
    infolen: usize,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe {
        kdf_derive(
            kctx,
            okm,
            okmlen,
            EVP_KDF_HKDF_MODE_EXPAND_ONLY,
            ptr::null(),
            0,
            prk,
            prklen,
            info,
            infolen,
        )
    }
}

/// `int ossl_hpke_labeled_extract(...)` — `hpke_util.c:295`.
///
/// `labeled_ikm = concat("HPKE-v1", protocol_label, suiteid, label, ikm)`, exactly sized. The
/// authority builds it with `WPACKET`; the concatenation is written directly because the length is
/// the exact sum and the `WPACKET` failure arm (`hpke_util.c:329`) is unreachable. See the module
/// doc.
///
/// # Safety
/// `kctx` live; `prk` writable for `prklen`; `suiteid`/`ikm` readable for their lengths.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn hpke_labeled_extract(
    kctx: *mut EvpKdfCtx,
    prk: *mut c_uchar,
    prklen: usize,
    salt: *const c_uchar,
    saltlen: usize,
    protocol_label: &[u8],
    suiteid: *const c_uchar,
    suiteidlen: usize,
    label: &[u8],
    ikm: *const c_uchar,
    ikmlen: usize,
) -> c_int {
    let labeled_ikmlen =
        LABEL_HPKEV1.len() + protocol_label.len() + suiteidlen + label.len() + ikmlen;
    let labeled_ikm = CRYPTO_malloc(labeled_ikmlen, FILE_HPKE_UTIL, 316).cast::<c_uchar>();
    if labeled_ikm.is_null() {
        return 0;
    }

    // SAFETY: the destination was sized as the exact sum below and each copy is of its own length.
    unsafe {
        let mut off = 0usize;
        ptr::copy_nonoverlapping(
            LABEL_HPKEV1.as_ptr(),
            labeled_ikm.add(off),
            LABEL_HPKEV1.len(),
        );
        off += LABEL_HPKEV1.len();
        ptr::copy_nonoverlapping(
            protocol_label.as_ptr(),
            labeled_ikm.add(off),
            protocol_label.len(),
        );
        off += protocol_label.len();
        if suiteidlen > 0 {
            ptr::copy_nonoverlapping(suiteid, labeled_ikm.add(off), suiteidlen);
        }
        off += suiteidlen;
        ptr::copy_nonoverlapping(label.as_ptr(), labeled_ikm.add(off), label.len());
        off += label.len();
        if ikmlen > 0 {
            ptr::copy_nonoverlapping(ikm, labeled_ikm.add(off), ikmlen);
        }
    }

    // SAFETY: `kctx` is live and `labeled_ikm` holds `labeled_ikmlen` bytes.
    let ret = unsafe {
        hpke_kdf_extract(
            kctx,
            prk,
            prklen,
            salt,
            saltlen,
            labeled_ikm,
            labeled_ikmlen,
        )
    };
    // SAFETY: the buffer is this call's own and just used.
    unsafe {
        cleanse_ptr(labeled_ikm, labeled_ikmlen);
        CRYPTO_free(labeled_ikm.cast::<c_void>(), FILE_HPKE_UTIL, 338);
    }
    ret
}

/// `int ossl_hpke_labeled_expand(...)` — `hpke_util.c:345`.
///
/// `labeled_info = concat(okmlen as u16 big-endian, "HPKE-v1", protocol_label, suiteid, label,
/// info)`, exactly sized; the `WPACKET` failure arm (`hpke_util.c:380`) is unreachable for the
/// same reason as the extract's.
///
/// # Safety
/// `kctx` live; `okm` writable for `okmlen`; `prk`/`info` readable for their lengths.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn hpke_labeled_expand(
    kctx: *mut EvpKdfCtx,
    okm: *mut c_uchar,
    okmlen: usize,
    prk: *const c_uchar,
    prklen: usize,
    protocol_label: &[u8],
    suiteid: *const c_uchar,
    suiteidlen: usize,
    label: &[u8],
    info: *const c_uchar,
    infolen: usize,
) -> c_int {
    let labeled_infolen = 2
        + okmlen
        + prklen
        + LABEL_HPKEV1.len()
        + protocol_label.len()
        + suiteidlen
        + label.len()
        + infolen;
    let labeled_info = CRYPTO_malloc(labeled_infolen, FILE_HPKE_UTIL, 366).cast::<c_uchar>();
    if labeled_info.is_null() {
        return 0;
    }

    // SAFETY: the destination was sized as the exact sum below and each copy is of its own length.
    unsafe {
        let mut off = 0usize;
        // `WPACKET_put_bytes_u16(&pkt, okmlen)` — big-endian, two octets.
        *labeled_info.add(off) = ((okmlen >> 8) & 0xff) as c_uchar;
        *labeled_info.add(off + 1) = (okmlen & 0xff) as c_uchar;
        off += 2;
        ptr::copy_nonoverlapping(
            LABEL_HPKEV1.as_ptr(),
            labeled_info.add(off),
            LABEL_HPKEV1.len(),
        );
        off += LABEL_HPKEV1.len();
        ptr::copy_nonoverlapping(
            protocol_label.as_ptr(),
            labeled_info.add(off),
            protocol_label.len(),
        );
        off += protocol_label.len();
        if suiteidlen > 0 {
            ptr::copy_nonoverlapping(suiteid, labeled_info.add(off), suiteidlen);
        }
        off += suiteidlen;
        ptr::copy_nonoverlapping(label.as_ptr(), labeled_info.add(off), label.len());
        off += label.len();
        if infolen > 0 {
            ptr::copy_nonoverlapping(info, labeled_info.add(off), infolen);
        }
    }

    // SAFETY: `kctx` is live and `labeled_info` holds `labeled_infolen` bytes.
    let ret = unsafe {
        hpke_kdf_expand(
            kctx,
            okm,
            okmlen,
            prk,
            prklen,
            labeled_info,
            labeled_infolen,
        )
    };
    // SAFETY: the buffer is this call's own and just used.
    unsafe { CRYPTO_free(labeled_info.cast::<c_void>(), FILE_HPKE_UTIL, 388) };
    ret
}

/// The crate's `cleanse` for a buffer that may be zero bytes long, which the crate's own
/// `cleanse` accepts.
///
/// # Safety
/// `p` must be writable for `len` bytes.
unsafe fn cleanse_ptr(p: *mut c_uchar, len: usize) {
    // SAFETY: `p` is writable for `len` per the contract.
    unsafe { crate::runtime::mem::cleanse(p, len) };
}

/// `EVP_KDF_CTX *ossl_kdf_ctx_create(const char *kdfname, const char *mdname,
///     OSSL_LIB_CTX *libctx, const char *propq)` — `hpke_util.c:393`.
///
/// # Safety
/// `kdfname`/`mdname` NULL or NUL-terminated; `libctx` NULL or live; `propq` NULL or
/// NUL-terminated.
pub(crate) unsafe fn kdf_ctx_create(
    kdfname: *const c_char,
    mdname: *const c_char,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpKdfCtx {
    // SAFETY: forwarded under this function's contract.
    let kdf: *mut EvpKdf = unsafe { EVP_KDF_fetch(libctx, kdfname, propq) };
    if kdf.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_UTIL_401) };
        return ptr::null_mut();
    }
    // SAFETY: `kdf` is live and this call owns the reference `EVP_KDF_fetch` returned.
    let kctx = unsafe { EVP_KDF_CTX_new(kdf) };
    // SAFETY: `kdf` is this call's own reference.
    unsafe { EVP_KDF_free(kdf) };
    if !kctx.is_null() && !mdname.is_null() {
        let mut params: [OsslParam; 3] = [OSSL_PARAM_construct_end(); 3];
        // SAFETY: each constructor writes one entry and the array has three.
        unsafe {
            params[0] =
                OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, mdname.cast_mut(), 0);
            if !propq.is_null() {
                params[1] = OSSL_PARAM_construct_utf8_string(
                    OSSL_KDF_PARAM_PROPERTIES,
                    propq.cast_mut(),
                    0,
                );
            }
        }
        // SAFETY: `kctx` is live and `params` is terminated.
        if unsafe { EVP_KDF_CTX_set_params(kctx, params.as_ptr()) } <= 0 {
            // SAFETY: `kctx` is this call's own context.
            unsafe { EVP_KDF_CTX_free(kctx) };
            return ptr::null_mut();
        }
    }
    kctx
}

/// `static uint16_t synonyms_name2id(const char *st, const synonymttab_t *synp,
///     size_t arrsize)` — `hpke_util.c:430`.
///
/// The comparison is `OPENSSL_strcasecmp`, which on this profile is the platform's
/// `strcasecmp`; ASCII case folding is the transcription, and the probe's synonyms are ASCII.
fn synonyms_name2id(st: &[u8], tab: &[(u16, [&str; 4])]) -> u16 {
    for (id, synonyms) in tab.iter() {
        for syn in synonyms.iter() {
            if ascii_case_eq(st, syn.as_bytes()) {
                return *id;
            }
        }
    }
    0
}

/// ASCII-only case-insensitive comparison, `strcasecmp`'s behaviour on the probe's inputs.
fn ascii_case_eq(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// `int ossl_hpke_str2suite(const char *suitestr, OSSL_HPKE_SUITE *suite)` —
/// `hpke_util.c:450`.
///
/// The delimiter counting and the "no delimiter at the end" test are the authority's, and both
/// refuse **silently** while the length and NULL checks raise. That difference is what the court's
/// `str2suite` arms separate.
///
/// # Safety
/// `suitestr` NULL or NUL-terminated; `suite` NULL or writable.
unsafe fn hpke_str2suite(suitestr: *const c_char, suite: *mut OsslHpkeSuite) -> c_int {
    let mut ids = [0u16; 3];
    let mut delim_count: c_int = 0;

    if suitestr.is_null() || suite.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_UTIL_459) };
        return 0;
    }
    // SAFETY: `suitestr` is NUL-terminated per the contract.
    if unsafe { *suitestr } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_UTIL_459) };
        return 0;
    }
    // `OPENSSL_strnlen(suitestr, OSSL_HPKE_MAX_SUITESTR)`.
    // SAFETY: `suitestr` is NUL-terminated and `OSSL_HPKE_MAX_SUITESTR` bounds the read.
    let inplen = unsafe { c_strnlen(suitestr, OSSL_HPKE_MAX_SUITESTR) };
    if inplen >= OSSL_HPKE_MAX_SUITESTR {
        // SAFETY: a compile-time constant site.
        unsafe { raise_site(&err_sites::HPKE_UTIL_464) };
        return 0;
    }
    // We don't want a delimiter at the end of the string.
    // SAFETY: `inplen >= 1` here (a non-empty string shorter than the bound).
    if unsafe { *suitestr.add(inplen - 1) } == OSSL_HPKE_STR_DELIMCHAR {
        return 0;
    }
    // We want exactly two delimiters in the input string.
    for i in 0..inplen {
        // SAFETY: `i < inplen` and the string is `inplen` bytes plus a NUL.
        if unsafe { *suitestr.add(i) } == OSSL_HPKE_STR_DELIMCHAR {
            delim_count += 1;
        }
    }
    if delim_count != 2 {
        return 0;
    }

    // The authority duplicates the string with `OPENSSL_memdup(suitestr, inplen + 1)` so it can
    // write the separators to NUL in place. This reads the same bytes without mutating the
    // caller's string, which is not observable: the only use of the copy is the parsing below.
    // SAFETY: `suitestr` is readable for `inplen` bytes.
    let bytes: &[u8] = unsafe { core::slice::from_raw_parts(suitestr.cast::<u8>(), inplen) };
    let mut labels = 0usize;
    let mut pieces = bytes.split(|b| *b == b',');
    while labels < 3 {
        // SAFETY: `split` yields the fields the delimiter count guarantees; a shorter iterator is
        // the authority's `st == NULL` and leaves `labels < 3`, which is a refusal.
        let Some(piece) = pieces.next() else {
            break;
        };
        let id = match labels {
            0 => synonyms_name2id(piece, &KEMSTRTAB),
            1 => synonyms_name2id(piece, &KDFSTRTAB),
            _ => synonyms_name2id(piece, &AEADSTRTAB),
        };
        if id == 0 {
            // `goto fail`, with `result` still 0.
            return 0;
        }
        ids[labels] = id;
        labels += 1;
    }
    if labels != 3 {
        return 0;
    }
    // SAFETY: `suite` is non-NULL and writable per the contract.
    unsafe {
        (*suite).kem_id = ids[0];
        (*suite).kdf_id = ids[1];
        (*suite).aead_id = ids[2];
    }
    1
}

/// `OPENSSL_strnlen(s, max)` — the length of the NUL-terminated string bounded by `max`.
///
/// # Safety
/// `s` must be NUL-terminated within `max` bytes.
unsafe fn c_strnlen(s: *const c_char, max: usize) -> usize {
    let mut n = 0;
    while n < max {
        // SAFETY: `n < max` and `s` is NUL-terminated within `max` bytes per the contract.
        if unsafe { *s.add(n) } == 0 {
            break;
        }
        n += 1;
    }
    n
}

// ---------------------------------------------------------------------------------------------
// The object — `struct ossl_hpke_ctx_st`, `hpke.c:48`.
// ---------------------------------------------------------------------------------------------

/// `OSSL_HPKE_SUITE` — `include/openssl/hpke.h:80`. Three `uint16_t` code points.
///
/// `pub` and `#[repr(C)]` because it is passed **by value** to eight of the exports, so the layout
/// is the ABI.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OsslHpkeSuite {
    /// `uint16_t kem_id`.
    pub kem_id: u16,
    /// `uint16_t kdf_id`.
    pub kdf_id: u16,
    /// `uint16_t aead_id`.
    pub aead_id: u16,
}

/// `struct ossl_hpke_ctx_st` — `hpke.c:48`.
///
/// `pub` for the reason every internal type in an exported signature is. Every field is
/// `pub(crate)`. The `OSSL_HPKE_CTX *` the caller holds is opaque in the installed header
/// (`hpke.h:106`), so only the crate can reach these fields.
#[repr(C)]
pub struct OsslHpkeCtx {
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `char *propq`.
    pub(crate) propq: *mut c_char,
    /// `int mode`.
    pub(crate) mode: c_int,
    /// `OSSL_HPKE_SUITE suite`.
    pub(crate) suite: OsslHpkeSuite,
    /// `const OSSL_HPKE_KEM_INFO *kem_info`.
    pub(crate) kem_info: Option<&'static HpkeKemInfo>,
    /// `const OSSL_HPKE_KDF_INFO *kdf_info`.
    pub(crate) kdf_info: Option<&'static HpkeKdfInfo>,
    /// `const OSSL_HPKE_AEAD_INFO *aead_info`.
    pub(crate) aead_info: Option<&'static HpkeAeadInfo>,
    /// `EVP_CIPHER *aead_ciph`.
    pub(crate) aead_ciph: *mut EvpCipher,
    /// `int role` — sender (0) or receiver (1).
    pub(crate) role: c_int,
    /// `uint64_t seq` — the AEAD sequence number.
    pub(crate) seq: u64,
    /// `unsigned char *shared_secret` — the KEM output `zz`.
    pub(crate) shared_secret: *mut c_uchar,
    /// `size_t shared_secretlen`.
    pub(crate) shared_secretlen: usize,
    /// `unsigned char *key` — the final AEAD key.
    pub(crate) key: *mut c_uchar,
    /// `size_t keylen`.
    pub(crate) keylen: usize,
    /// `unsigned char *nonce` — the AEAD base nonce.
    pub(crate) nonce: *mut c_uchar,
    /// `size_t noncelen`.
    pub(crate) noncelen: usize,
    /// `unsigned char *exportersec` — the exporter secret.
    pub(crate) exportersec: *mut c_uchar,
    /// `size_t exporterseclen`.
    pub(crate) exporterseclen: usize,
    /// `char *pskid`.
    pub(crate) pskid: *mut c_char,
    /// `unsigned char *psk`.
    pub(crate) psk: *mut c_uchar,
    /// `size_t psklen`.
    pub(crate) psklen: usize,
    /// `EVP_PKEY *authpriv` — the sender's authentication private key.
    pub(crate) authpriv: *mut EvpPkey,
    /// `unsigned char *authpub` — the auth public key.
    pub(crate) authpub: *mut c_uchar,
    /// `size_t authpublen`.
    pub(crate) authpublen: usize,
    /// `unsigned char *ikme` — the IKM for deterministic sender keygen.
    pub(crate) ikme: *mut c_uchar,
    /// `size_t ikmelen`.
    pub(crate) ikmelen: usize,
}

// ---------------------------------------------------------------------------------------------
// The file-local statics — `hpke.c:82`..`:641`.
// ---------------------------------------------------------------------------------------------

/// `static int hpke_kem_id_nist_curve(uint16_t kem_id)` — `hpke.c:82`.
fn hpke_kem_id_nist_curve(kem_id: u16) -> bool {
    match kem_info_find_id(kem_id) {
        Some(info) => info.groupname.is_some(),
        None => false,
    }
}

/// `static EVP_PKEY *evp_pkey_new_raw_nist_public_key(...)` — `hpke.c:102`.
///
/// The NIST-curve arm of the import: it parameter-generates an `"EC"` key with the group name and
/// then sets the encoded public point. `EVP_PKEY_set1_encoded_public_key`'s own size check is what
/// makes a malformed buffer a refusal rather than a bad key.
///
/// # Safety
/// `propq` NULL or NUL-terminated; `gname` NUL-terminated; `buf` readable for `buflen`.
unsafe fn evp_pkey_new_raw_nist_public_key(
    libctx: *mut c_void,
    propq: *const c_char,
    gname: *const c_char,
    buf: *const c_uchar,
    buflen: usize,
) -> *mut EvpPkey {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut ret: *mut EvpPkey = ptr::null_mut();
    // SAFETY: forwarded under this function's contract.
    let cctx: *mut EvpPkeyCtx =
        unsafe { EVP_PKEY_CTX_new_from_name(libctx, c"EC".as_ptr(), propq) };

    // SAFETY: one constructor writes one entry and the array has two.
    unsafe {
        params[0] =
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, gname.cast_mut(), 0);
    }
    // SAFETY: `cctx` is NULL or live, and each call accepts that state as the authority's does.
    let ok = unsafe {
        !cctx.is_null()
            && EVP_PKEY_paramgen_init(cctx) > 0
            && EVP_PKEY_CTX_set_params(cctx, params.as_ptr()) > 0
            && EVP_PKEY_paramgen(cctx, &mut ret) > 0
            && EVP_PKEY_set1_encoded_public_key(ret, buf, buflen) == 1
    };
    if !ok {
        // SAFETY: `cctx` is NULL or this call's own context; both free paths accept that.
        unsafe {
            EVP_PKEY_CTX_free(cctx);
            EVP_PKEY_free(ret);
        }
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_122) };
        return ptr::null_mut();
    }
    // SAFETY: `cctx` is this call's own context.
    unsafe { EVP_PKEY_CTX_free(cctx) };
    ret
}

/// `static int hpke_aead_dec(...)` — `hpke.c:141`.
///
/// The decrypt half of RFC 9180's `Open`. The length test first: a ciphertext no longer than the
/// tag, a plaintext buffer smaller than the ciphertext less its tag, or either length past
/// `INT_MAX` are all `ERR_R_PASSED_INVALID_ARGUMENT` before a context is built.
///
/// The control flow is the authority's `goto err`: every failure after the context exists cleanses
/// the **caller's** plaintext buffer to the length the function has set so far, then releases the
/// context. The cleansed length is `*ptlen`, which the second `EVP_DecryptUpdate` has already
/// updated — so the wipe covers the bytes written, not the buffer's whole capacity.
///
/// # Safety
/// `hctx` live; `iv` readable for `hctx->noncelen`; `aad` readable for `aadlen` unless 0; `ct`
/// readable for `ctlen`; `pt` writable for `*ptlen`; `ptlen` writable.
#[allow(clippy::too_many_arguments)]
unsafe fn hpke_aead_dec(
    hctx: *mut OsslHpkeCtx,
    iv: *const c_uchar,
    aad: *const c_uchar,
    aadlen: usize,
    ct: *const c_uchar,
    ctlen: usize,
    pt: *mut c_uchar,
    ptlen: *mut usize,
) -> c_int {
    let mut erv = 0;
    let mut len: c_int = 0;
    // SAFETY: `hctx` is live per the contract, so `aead_info` is set.
    let taglen = unsafe { (*hctx).aead_info }.map_or(0, |i| i.taglen);

    // SAFETY: `ptlen` is a live out-parameter per this function's contract.
    let ptlen_in = unsafe { *ptlen };
    if ctlen <= taglen
        || ptlen_in < ctlen - taglen
        || aadlen > c_int::MAX as usize
        || ctlen > c_int::MAX as usize
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_154) };
        return 0;
    }
    // Create and initialise the context.
    // SAFETY: no preconditions.
    let ctx = EVP_CIPHER_CTX_new();
    if ctx.is_null() {
        return 0;
    }
    'body: {
        // SAFETY: `ctx` is live; `hctx->aead_ciph` is the fetched cipher.
        if unsafe {
            EVP_DecryptInit_ex(
                ctx,
                (*hctx).aead_ciph,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
            )
        } != 1
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_162) };
            break 'body;
        }
        // SAFETY: `ctx` is live.
        if unsafe {
            EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_AEAD_SET_IVLEN,
                (*hctx).noncelen as c_int,
                ptr::null_mut(),
            )
        } != 1
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_168) };
            break 'body;
        }
        // Initialise key and IV.
        // SAFETY: `ctx` is live; `hctx->key`/`iv` are readable.
        if unsafe { EVP_DecryptInit_ex(ctx, ptr::null(), ptr::null_mut(), (*hctx).key, iv) } != 1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_173) };
            break 'body;
        }
        // Provide AAD.
        if aadlen != 0 && !aad.is_null() {
            // SAFETY: `ctx` is live; `aad` readable for `aadlen`.
            if unsafe { EVP_DecryptUpdate(ctx, ptr::null_mut(), &mut len, aad, aadlen as c_int) }
                != 1
            {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::HPKE_179) };
                break 'body;
            }
        }
        // SAFETY: `ctx` is live; `ct` readable for `ctlen - taglen`.
        if unsafe { EVP_DecryptUpdate(ctx, pt, &mut len, ct, (ctlen - taglen) as c_int) } != 1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_184) };
            break 'body;
        }
        // SAFETY: `ptlen` is writable per the contract.
        unsafe { *ptlen = len as usize };
        // SAFETY: `ctx` is live; the tag pointer is inside `ct`.
        if unsafe {
            EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_AEAD_SET_TAG,
                taglen as c_int,
                ct.add(ctlen - taglen).cast_mut().cast::<c_void>(),
            )
        } == 0
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_190) };
            break 'body;
        }
        // Finalise decryption.
        // SAFETY: `ctx` is live; `pt + len` has room for the final block.
        if unsafe { EVP_DecryptFinal_ex(ctx, pt.add(len as usize), &mut len) } <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_195) };
            break 'body;
        }
        erv = 1;
    }
    if erv != 1 {
        // SAFETY: `pt` is the caller's buffer and `*ptlen` is what the function has written.
        unsafe { cleanse_ptr(pt, *ptlen) };
    }
    // SAFETY: `ctx` is this call's own context.
    unsafe { EVP_CIPHER_CTX_free(ctx) };
    erv
}

/// `static int hpke_aead_enc(...)` — `hpke.c:219`.
///
/// The encrypt half. The tag is fetched into a stack buffer and appended to the ciphertext, which
/// is why `ctlen` is "room for the plaintext plus the tag on input, exact on output".
///
/// # Safety
/// `hctx` live; `iv` readable for `hctx->noncelen`; `aad` readable for `aadlen` unless 0; `pt`
/// readable for `ptlen`; `ct` writable for `*ctlen`; `ctlen` writable.
#[allow(clippy::too_many_arguments)]
unsafe fn hpke_aead_enc(
    hctx: *mut OsslHpkeCtx,
    iv: *const c_uchar,
    aad: *const c_uchar,
    aadlen: usize,
    pt: *const c_uchar,
    ptlen: usize,
    ct: *mut c_uchar,
    ctlen: *mut usize,
) -> c_int {
    let mut erv = 0;
    let mut len: c_int = 0;
    let mut tag = [0 as c_uchar; EVP_MAX_AEAD_TAG_LENGTH];
    // SAFETY: `hctx` is live per the contract, so `aead_info` is set.
    let taglen = unsafe { (*hctx).aead_info }.map_or(0, |i| i.taglen);

    // SAFETY: `ctlen` is a live out-parameter per this function's contract.
    let ctlen_in = unsafe { *ctlen };
    if ctlen_in <= taglen
        || ptlen > ctlen_in - taglen
        || aadlen > c_int::MAX as usize
        || ptlen > c_int::MAX as usize
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_233) };
        return 0;
    }
    // `ossl_assert(taglen <= sizeof(tag))` is the authority's non-fatal assertion form under
    // `NDEBUG`, and the `if (!...)` that follows is a live refusal.
    if taglen > EVP_MAX_AEAD_TAG_LENGTH {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_237) };
        return 0;
    }
    // Create and initialise the context.
    // SAFETY: no preconditions.
    let ctx = EVP_CIPHER_CTX_new();
    if ctx.is_null() {
        return 0;
    }
    'body: {
        // SAFETY: `ctx` is live; `hctx->aead_ciph` is the fetched cipher.
        if unsafe {
            EVP_EncryptInit_ex(
                ctx,
                (*hctx).aead_ciph,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
            )
        } != 1
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_245) };
            break 'body;
        }
        // SAFETY: `ctx` is live.
        if unsafe {
            EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_AEAD_SET_IVLEN,
                (*hctx).noncelen as c_int,
                ptr::null_mut(),
            )
        } != 1
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_251) };
            break 'body;
        }
        // SAFETY: `ctx` is live; `hctx->key`/`iv` are readable.
        if unsafe { EVP_EncryptInit_ex(ctx, ptr::null(), ptr::null_mut(), (*hctx).key, iv) } != 1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_256) };
            break 'body;
        }
        // Provide any AAD data.
        if aadlen != 0 && !aad.is_null() {
            // SAFETY: `ctx` is live; `aad` readable for `aadlen`.
            if unsafe { EVP_EncryptUpdate(ctx, ptr::null_mut(), &mut len, aad, aadlen as c_int) }
                != 1
            {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::HPKE_262) };
                break 'body;
            }
        }
        // SAFETY: `ctx` is live; `pt` readable for `ptlen`, `ct` writable for `ptlen`.
        if unsafe { EVP_EncryptUpdate(ctx, ct, &mut len, pt, ptlen as c_int) } != 1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_267) };
            break 'body;
        }
        // SAFETY: `ctlen` is writable per the contract.
        unsafe { *ctlen = len as usize };
        // Finalise the encryption.
        // SAFETY: `ctx` is live; `ct + len` has room for the final block.
        if unsafe { EVP_EncryptFinal_ex(ctx, ct.add(len as usize), &mut len) } != 1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_273) };
            break 'body;
        }
        // SAFETY: `ctlen` is writable.
        unsafe { *ctlen += len as usize };
        // Get tag. Not a duplicate so needs to be added to the ciphertext.
        // SAFETY: `ctx` is live; `tag` is writable for `taglen <= 16`.
        if unsafe {
            EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_AEAD_GET_TAG,
                taglen as c_int,
                tag.as_mut_ptr().cast(),
            )
        } != 1
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_279) };
            break 'body;
        }
        // SAFETY: the destination is inside `ct`'s capacity and the source is `tag`.
        unsafe {
            ptr::copy_nonoverlapping(tag.as_ptr(), ct.add(*ctlen), taglen);
            *ctlen += taglen;
        }
        erv = 1;
    }
    if erv != 1 {
        // SAFETY: `ct` is the caller's buffer and `*ctlen` is what the function has written.
        unsafe { cleanse_ptr(ct, *ctlen) };
    }
    // SAFETY: `ctx` is this call's own context.
    unsafe { EVP_CIPHER_CTX_free(ctx) };
    erv
}

/// `static int hpke_mode_check(unsigned int mode)` — `hpke.c:298`.
fn hpke_mode_check(mode: c_int) -> bool {
    matches!(
        mode,
        OSSL_HPKE_MODE_BASE | OSSL_HPKE_MODE_PSK | OSSL_HPKE_MODE_AUTH | OSSL_HPKE_MODE_PSKAUTH
    )
}

/// `static int hpke_suite_check(OSSL_HPKE_SUITE suite, ...)` — `hpke.c:317`.
///
/// The three lookups in order, each of which raises its own provider reason on a miss; the
/// optional out-parameters are filled only after all three succeed, which is what makes a partial
/// suite a refusal and not a partially-filled result.
fn hpke_suite_check(
    suite: OsslHpkeSuite,
) -> Option<(
    &'static HpkeKemInfo,
    &'static HpkeKdfInfo,
    &'static HpkeAeadInfo,
)> {
    let kem_info = kem_info_find_id(suite.kem_id)?;
    let kdf_info = kdf_info_find_id(suite.kdf_id)?;
    let aead_info = aead_info_find_id(suite.aead_id)?;
    Some((kem_info, kdf_info, aead_info))
}

/// `static int hpke_expansion(OSSL_HPKE_SUITE suite, size_t *enclen, size_t clearlen,
///     size_t *cipherlen)` — `hpke.c:394`.
///
/// The size arithmetic both `OSSL_HPKE_get_ciphertext_size` and
/// `OSSL_HPKE_get_public_encap_size` share. The two callers always pass non-NULL out-parameters,
/// so the authority's own `cipherlen == NULL || enclen == NULL` refusal (`hpke.c:402`, raising at
/// `:403`) is **unreachable** and is not driven; the suite failure raises the lookup's own reason
/// **and then** `ERR_R_PASSED_INVALID_ARGUMENT` at `:407`, which the transcription preserves.
fn hpke_expansion(suite: OsslHpkeSuite, clearlen: usize) -> Option<(usize, usize)> {
    let (kem_info, _kdf_info, aead_info) = match hpke_suite_check(suite) {
        Some(v) => v,
        None => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_407) };
            return None;
        }
    };
    Some((kem_info.nenc, clearlen + aead_info.taglen))
}

/// `static size_t hpke_seqnonce2buf(OSSL_HPKE_CTX *ctx, unsigned char *buf, size_t blen)` —
/// `hpke.c:422`.
///
/// The 64-bit sequence number, big-endian in the last eight bytes of a zeroed buffer, XOR'd with
/// the base nonce. A `blen` that is not the nonce length is a silent 0.
///
/// # Safety
/// `ctx` NULL or live; `buf` writable for `blen`.
unsafe fn hpke_seqnonce2buf(ctx: *mut OsslHpkeCtx, buf: *mut c_uchar, blen: usize) -> usize {
    if ctx.is_null() || blen < core::mem::size_of::<u64>() {
        return 0;
    }
    // SAFETY: `ctx` is non-NULL on this arm.
    if blen != unsafe { (*ctx).noncelen } {
        return 0;
    }
    // SAFETY: `ctx` is live on this arm.
    let mut s = unsafe { (*ctx).seq };
    // SAFETY: `buf` is writable for `blen` bytes.
    unsafe { ptr::write_bytes(buf, 0, blen) };
    for i in 0..core::mem::size_of::<u64>() {
        // SAFETY: `i < 8 <= blen`.
        unsafe { *buf.add(blen - i - 1) = (s & 0xff) as c_uchar };
        s >>= 8;
    }
    for i in 0..blen {
        // SAFETY: `i < blen`; `ctx->nonce` is `noncelen == blen` bytes.
        unsafe { *buf.add(i) ^= *(*ctx).nonce.add(i) };
    }
    blen
}

/// `static int hpke_encap(...)` — `hpke.c:450`.
///
/// The KEM half. One encapsulation per context is a hard rule (`ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED`
/// on a second call), and the first `EVP_PKEY_encapsulate` is a size query whose answer is then
/// used to allocate the shared secret.
///
/// # Safety
/// `ctx` NULL or live; `enc` writable for `*enclen`; `enclen` writable; `pub` readable for
/// `publen`.
unsafe fn hpke_encap(
    ctx: *mut OsslHpkeCtx,
    enc: *mut c_uchar,
    enclen: *mut usize,
    pub_: *const c_uchar,
    publen: usize,
) -> c_int {
    let mut erv = 0;
    let mut params: [OsslParam; 3] = [OSSL_PARAM_construct_end(); 3];
    let mut p = 0usize;
    let mut lsslen: usize = 0;
    let mut pctx: *mut EvpPkeyCtx = ptr::null_mut();

    if ctx.is_null() || enc.is_null() || enclen.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_462) };
        return 0;
    }
    // SAFETY: `enclen` is a live out-parameter on this arm, the NULL case being refused above.
    if unsafe { *enclen } == 0 || pub_.is_null() || publen == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_462) };
        return 0;
    }
    // SAFETY: `ctx` is live on this arm.
    if !unsafe { (*ctx).shared_secret }.is_null() {
        // Only run the KEM once per OSSL_HPKE_CTX.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_467) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    let Some(kem_info) = kem_info_find_id(unsafe { (*ctx).suite }.kem_id) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_472) };
        return 0;
    };
    // SAFETY: `ctx` is live.
    let pkr: *mut EvpPkey = if hpke_kem_id_nist_curve(unsafe { (*ctx).suite }.kem_id) {
        // SAFETY: `ctx` is live; `kem_info.groupname` is `Some` on this arm.
        let gname = kem_info.groupname.map_or(ptr::null(), |g| g.as_ptr());
        // SAFETY: forwarded under this function's contract.
        unsafe {
            evp_pkey_new_raw_nist_public_key((*ctx).libctx, (*ctx).propq, gname, pub_, publen)
        }
    } else {
        // SAFETY: `ctx` is live; `kem_info.keytype` is NUL-terminated.
        unsafe {
            EVP_PKEY_new_raw_public_key_ex(
                (*ctx).libctx,
                kem_info.keytype.as_ptr(),
                (*ctx).propq,
                pub_,
                publen,
            )
        }
    };
    'body: {
        if pkr.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_485) };
            break 'body;
        }
        // SAFETY: `ctx` is live; `pkr` is this call's own key.
        pctx = unsafe { EVP_PKEY_CTX_new_from_pkey((*ctx).libctx, pkr, (*ctx).propq) };
        if pctx.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_490) };
            break 'body;
        }
        // SAFETY: each constructor writes one entry and `params` has three.
        unsafe {
            params[p] = OSSL_PARAM_construct_utf8_string(
                OSSL_KEM_PARAM_OPERATION,
                OSSL_KEM_PARAM_OPERATION_DHKEM.cast_mut(),
                0,
            );
            p += 1;
            if !(*ctx).ikme.is_null() {
                params[p] = OSSL_PARAM_construct_octet_string(
                    OSSL_KEM_PARAM_IKME,
                    (*ctx).ikme.cast::<c_void>(),
                    (*ctx).ikmelen,
                );
                p += 1;
            }
            params[p] = OSSL_PARAM_construct_end();
        }
        // SAFETY: `ctx` and `pctx` are live.
        let auth = unsafe { (*ctx).mode } == OSSL_HPKE_MODE_AUTH
            || unsafe { (*ctx).mode } == OSSL_HPKE_MODE_PSKAUTH;
        if auth {
            // SAFETY: `pctx` and the auth key are live.
            if unsafe { EVP_PKEY_auth_encapsulate_init(pctx, (*ctx).authpriv, params.as_ptr()) }
                != 1
            {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::HPKE_506) };
                break 'body;
            }
        } else {
            // SAFETY: `pctx` is live and `params` is terminated.
            if unsafe { EVP_PKEY_encapsulate_init(pctx, params.as_ptr()) } != 1 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::HPKE_511) };
                break 'body;
            }
        }
        // SAFETY: `enclen` is writable per the contract.
        let mut lenclen = unsafe { *enclen };
        // SAFETY: `pctx` is live; the NULL out/in pair is the size query.
        if unsafe {
            EVP_PKEY_encapsulate(
                pctx,
                ptr::null_mut(),
                &mut lenclen,
                ptr::null_mut(),
                &mut lsslen,
            )
        } != 1
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_517) };
            break 'body;
        }
        // SAFETY: `enclen` is the caller's live out-parameter and the size query did not write it.
        if lenclen > unsafe { *enclen } {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_521) };
            break 'body;
        }
        // SAFETY: `lsslen` was filled by the size query.
        let ss = CRYPTO_malloc(lsslen, FILE_HPKE, 524).cast::<c_uchar>();
        if ss.is_null() {
            break 'body;
        }
        // SAFETY: `ctx` is live per the contract.
        unsafe {
            (*ctx).shared_secret = ss;
            (*ctx).shared_secretlen = lsslen;
        }
        // SAFETY: `pctx` is live; `ss` is writable for `lsslen` and `enc` for `*enclen`.
        if unsafe {
            EVP_PKEY_encapsulate(
                pctx,
                enc,
                enclen,
                (*ctx).shared_secret,
                &mut (*ctx).shared_secretlen,
            )
        } != 1
        {
            // SAFETY: `ctx` is live and `shared_secret` is this call's own.
            unsafe {
                (*ctx).shared_secretlen = 0;
                CRYPTO_free((*ctx).shared_secret.cast::<c_void>(), FILE_HPKE, 532);
                (*ctx).shared_secret = ptr::null_mut();
            }
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_534) };
            break 'body;
        }
        erv = 1;
    }
    // SAFETY: both are NULL or this call's own.
    unsafe {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkr);
    }
    erv
}

/// `static int hpke_decap(...)` — `hpke.c:553`.
///
/// # Safety
/// `ctx` NULL or live; `enc` readable for `enclen`; `priv` NULL or live.
unsafe fn hpke_decap(
    ctx: *mut OsslHpkeCtx,
    enc: *const c_uchar,
    enclen: usize,
    priv_: *mut EvpPkey,
) -> c_int {
    let mut erv = 0;
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut lsslen: usize = 0;
    let mut spub: *mut EvpPkey = ptr::null_mut();

    if ctx.is_null() || enc.is_null() || enclen == 0 || priv_.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_564) };
        return 0;
    }
    // SAFETY: `ctx` is live on this arm.
    if !unsafe { (*ctx).shared_secret }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_569) };
        return 0;
    }
    // SAFETY: `ctx` is live; `priv_` is the caller's live key.
    let pctx = unsafe { EVP_PKEY_CTX_new_from_pkey((*ctx).libctx, priv_, (*ctx).propq) };
    'body: {
        if pctx.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_574) };
            break 'body;
        }
        // SAFETY: one constructor writes one entry and the array has two.
        unsafe {
            params[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_KEM_PARAM_OPERATION,
                OSSL_KEM_PARAM_OPERATION_DHKEM.cast_mut(),
                0,
            );
        }
        // SAFETY: `ctx` is live.
        let auth = unsafe { (*ctx).mode } == OSSL_HPKE_MODE_AUTH
            || unsafe { (*ctx).mode } == OSSL_HPKE_MODE_PSKAUTH;
        if auth {
            // SAFETY: `ctx` is live.
            let Some(kem_info) = kem_info_find_id(unsafe { (*ctx).suite }.kem_id) else {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::HPKE_587) };
                break 'body;
            };
            // SAFETY: `ctx` is live.
            if hpke_kem_id_nist_curve(unsafe { (*ctx).suite }.kem_id) {
                // SAFETY: `ctx` is live; `groupname` is `Some` on this arm.
                let gname = kem_info.groupname.map_or(ptr::null(), |g| g.as_ptr());
                // SAFETY: forwarded under this function's contract.
                spub = unsafe {
                    evp_pkey_new_raw_nist_public_key(
                        (*ctx).libctx,
                        (*ctx).propq,
                        gname,
                        (*ctx).authpub,
                        (*ctx).authpublen,
                    )
                };
            } else {
                // SAFETY: `ctx` is live; `keytype` is NUL-terminated.
                spub = unsafe {
                    EVP_PKEY_new_raw_public_key_ex(
                        (*ctx).libctx,
                        kem_info.keytype.as_ptr(),
                        (*ctx).propq,
                        (*ctx).authpub,
                        (*ctx).authpublen,
                    )
                };
            }
            if spub.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::HPKE_603) };
                break 'body;
            }
            // SAFETY: `pctx` and `spub` are live; `params` is terminated.
            if unsafe { EVP_PKEY_auth_decapsulate_init(pctx, spub, params.as_ptr()) } != 1 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::HPKE_607) };
                break 'body;
            }
        } else {
            // SAFETY: `pctx` is live and `params` is terminated.
            if unsafe { EVP_PKEY_decapsulate_init(pctx, params.as_ptr()) } != 1 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::HPKE_612) };
                break 'body;
            }
        }
        // SAFETY: `pctx` is live; `enc` is readable for `enclen`.
        if unsafe { EVP_PKEY_decapsulate(pctx, ptr::null_mut(), &mut lsslen, enc, enclen) } != 1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_617) };
            break 'body;
        }
        // SAFETY: `lsslen` was filled by the size query.
        let ss = CRYPTO_malloc(lsslen, FILE_HPKE, 620).cast::<c_uchar>();
        if ss.is_null() {
            break 'body;
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).shared_secret = ss };
        // SAFETY: `pctx` is live; `ss` is writable for `lsslen`.
        if unsafe { EVP_PKEY_decapsulate(pctx, (*ctx).shared_secret, &mut lsslen, enc, enclen) }
            != 1
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_626) };
            break 'body;
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).shared_secretlen = lsslen };
        erv = 1;
    }
    // SAFETY: both are NULL or this call's own.
    unsafe {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(spub);
    }
    if erv == 0 {
        // SAFETY: `ctx` is live and `shared_secret` is NULL or this call's own block.
        unsafe {
            CRYPTO_free((*ctx).shared_secret.cast::<c_void>(), FILE_HPKE, 636);
            (*ctx).shared_secret = ptr::null_mut();
            (*ctx).shared_secretlen = 0;
        }
    }
    erv
}

/// `static int hpke_do_middle(OSSL_HPKE_CTX *ctx, const unsigned char *info, size_t infolen)` —
/// `hpke.c:654`.
///
/// The RFC 9180 key schedule: the two context hashes, the shared secret's extract, then the
/// nonce/key/exportersecret expands. Once per context (`exportersec != NULL` is the gate), and the
/// PSK modes require a psk, a non-zero psk length and a pskid before anything is computed.
///
/// # Safety
/// `ctx` NULL or live; `info` readable for `infolen` unless 0.
unsafe fn hpke_do_middle(ctx: *mut OsslHpkeCtx, info: *const c_uchar, infolen: usize) -> c_int {
    let mut erv = 0;
    let mut ks_context = [0 as c_uchar; OSSL_HPKE_MAXSIZE];
    let mut secret = [0 as c_uchar; OSSL_HPKE_MAXSIZE];
    let mut suitebuf = [0 as c_uchar; 6];

    if ctx.is_null() {
        return 0;
    }
    // Only let this be done once.
    // SAFETY: `ctx` is live per the contract.
    if !unsafe { (*ctx).exportersec }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_672) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    let suite = unsafe { (*ctx).suite };
    if kem_info_find_id(suite.kem_id).is_none() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_676) };
        return 0;
    }
    let Some(aead_info) = aead_info_find_id(suite.aead_id) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_681) };
        return 0;
    };
    let Some(kdf_info) = kdf_info_find_id(suite.kdf_id) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_686) };
        return 0;
    };
    // Create key schedule context.
    // SAFETY: `ctx` is live per the contract.
    ks_context[0] = (unsafe { (*ctx).mode } % 256) as c_uchar;
    let ks_contextcap = OSSL_HPKE_MAXSIZE - 1;
    let halflen = kdf_info.nh;
    if 2 * halflen > ks_contextcap {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_696) };
        return 0;
    }
    // Check a psk was set if in that mode.
    // SAFETY: `ctx` is live.
    let mode = unsafe { (*ctx).mode };
    if mode == OSSL_HPKE_MODE_PSK || mode == OSSL_HPKE_MODE_PSKAUTH {
        // SAFETY: `ctx` is live on this arm.
        let (psk, psklen, pskid) = unsafe { ((*ctx).psk, (*ctx).psklen, (*ctx).pskid) };
        if psk.is_null() || psklen == 0 || pskid.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_703) };
            return 0;
        }
    }
    // SAFETY: `ctx` is live; `mdname` is NUL-terminated.
    let kctx = unsafe {
        kdf_ctx_create(
            c"HKDF".as_ptr(),
            kdf_info.mdname.as_ptr(),
            (*ctx).libctx,
            (*ctx).propq,
        )
    };
    if kctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_709) };
        return 0;
    }
    'body: {
        // SAFETY: `ctx` is live; `psk == NULL` skips the `strlen`.
        let pskidlen = if unsafe { (*ctx).psk }.is_null() {
            0
        } else {
            // SAFETY: `pskid` is non-NULL on this arm and NUL-terminated.
            unsafe { c_strnlen((*ctx).pskid, usize::MAX) }
        };
        // Full suite details as per RFC9180 sec 5.1.
        suitebuf[0] = (suite.kem_id / 256) as c_uchar;
        suitebuf[1] = (suite.kem_id % 256) as c_uchar;
        suitebuf[2] = (suite.kdf_id / 256) as c_uchar;
        suitebuf[3] = (suite.kdf_id % 256) as c_uchar;
        suitebuf[4] = (suite.aead_id / 256) as c_uchar;
        suitebuf[5] = (suite.aead_id % 256) as c_uchar;

        // Extract and Expand variously.
        // SAFETY: `kctx` is live; each buffer is sized by the `halflen` arithmetic above.
        let r1 = unsafe {
            hpke_labeled_extract(
                kctx,
                ks_context.as_mut_ptr().add(1),
                halflen,
                ptr::null(),
                0,
                SEC51LABEL,
                suitebuf.as_ptr(),
                suitebuf.len(),
                PSKIDHASH_LABEL,
                (*ctx).pskid.cast::<c_uchar>(),
                pskidlen,
            )
        };
        if r1 != 1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_727) };
            break 'body;
        }
        // SAFETY: as above; the destination is the second half.
        let r2 = unsafe {
            hpke_labeled_extract(
                kctx,
                ks_context.as_mut_ptr().add(1 + halflen),
                halflen,
                ptr::null(),
                0,
                SEC51LABEL,
                suitebuf.as_ptr(),
                suitebuf.len(),
                INFOHASH_LABEL,
                info,
                infolen,
            )
        };
        if r2 != 1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_736) };
            break 'body;
        }
        let ks_contextlen = 1 + 2 * halflen;
        let secretlen = kdf_info.nh;
        if secretlen > OSSL_HPKE_MAXSIZE {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_742) };
            break 'body;
        }
        // SAFETY: `kctx` is live; `secret` has `secretlen <= 512` bytes; the empty secret is the
        // extraction's ikm when no psk was set.
        let r3 = unsafe {
            hpke_labeled_extract(
                kctx,
                secret.as_mut_ptr(),
                secretlen,
                (*ctx).shared_secret,
                (*ctx).shared_secretlen,
                SEC51LABEL,
                suitebuf.as_ptr(),
                suitebuf.len(),
                SECRET_LABEL,
                (*ctx).psk,
                (*ctx).psklen,
            )
        };
        if r3 != 1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_752) };
            break 'body;
        }
        if suite.aead_id != OSSL_HPKE_AEAD_ID_EXPORTONLY {
            // We only need nonce/key for non export AEADs.
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).noncelen = aead_info.nn };
            // SAFETY: `ctx` is live and `noncelen` is now the AEAD's nonce length.
            let nonce = unsafe { CRYPTO_malloc((*ctx).noncelen, FILE_HPKE, 758) }.cast::<c_uchar>();
            if nonce.is_null() {
                break 'body;
            }
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).nonce = nonce };
            // SAFETY: `kctx` is live; `nonce` writable for `noncelen`.
            if unsafe {
                hpke_labeled_expand(
                    kctx,
                    (*ctx).nonce,
                    (*ctx).noncelen,
                    secret.as_ptr(),
                    secretlen,
                    SEC51LABEL,
                    suitebuf.as_ptr(),
                    suitebuf.len(),
                    NONCE_LABEL,
                    ks_context.as_ptr(),
                    ks_contextlen,
                )
            } != 1
            {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::HPKE_767) };
                break 'body;
            }
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).keylen = aead_info.nk };
            // SAFETY: `ctx` is live and `keylen` is now the AEAD's key length.
            let key = unsafe { CRYPTO_malloc((*ctx).keylen, FILE_HPKE, 771) }.cast::<c_uchar>();
            if key.is_null() {
                break 'body;
            }
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).key = key };
            // SAFETY: `kctx` is live; `key` writable for `keylen`.
            if unsafe {
                hpke_labeled_expand(
                    kctx,
                    (*ctx).key,
                    (*ctx).keylen,
                    secret.as_ptr(),
                    secretlen,
                    SEC51LABEL,
                    suitebuf.as_ptr(),
                    suitebuf.len(),
                    KEY_LABEL,
                    ks_context.as_ptr(),
                    ks_contextlen,
                )
            } != 1
            {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::HPKE_780) };
                break 'body;
            }
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).exporterseclen = kdf_info.nh };
        // SAFETY: `ctx` is live and `exporterseclen` is the KDF's hash length.
        let es = unsafe { CRYPTO_malloc((*ctx).exporterseclen, FILE_HPKE, 785) }.cast::<c_uchar>();
        if es.is_null() {
            break 'body;
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).exportersec = es };
        // SAFETY: `kctx` is live; `exportersec` writable for `exporterseclen`.
        if unsafe {
            hpke_labeled_expand(
                kctx,
                (*ctx).exportersec,
                (*ctx).exporterseclen,
                secret.as_ptr(),
                secretlen,
                SEC51LABEL,
                suitebuf.as_ptr(),
                suitebuf.len(),
                EXP_LABEL,
                ks_context.as_ptr(),
                ks_contextlen,
            )
        } != 1
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_794) };
            break 'body;
        }
        erv = 1;
    }
    // SAFETY: NULL or this call's own context.
    unsafe { EVP_KDF_CTX_free(kctx) };
    erv
}

// ---------------------------------------------------------------------------------------------
// The exports — `hpke.c:811` onward.
// ---------------------------------------------------------------------------------------------

/// `OSSL_HPKE_CTX *OSSL_HPKE_CTX_new(int mode, OSSL_HPKE_SUITE suite, int role,
///     OSSL_LIB_CTX *libctx, const char *propq)` — `hpke.c:811`.
///
/// Three validations in the authority's order — mode, suite, role — and the AEAD fetch last. An
/// export-only suite fetches no cipher, which is why `aead_ciph` can legitimately be NULL for a
/// context that succeeds.
///
/// # Safety
/// `libctx` NULL or live; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HPKE_CTX_new(
    mode: c_int,
    suite: OsslHpkeSuite,
    role: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut OsslHpkeCtx {
    if !hpke_mode_check(mode) {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_820) };
        return ptr::null_mut();
    }
    let Some((kem_info, kdf_info, aead_info)) = hpke_suite_check(suite) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_824) };
        return ptr::null_mut();
    };
    if role != OSSL_HPKE_ROLE_SENDER && role != OSSL_HPKE_ROLE_RECEIVER {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_828) };
        return ptr::null_mut();
    }
    let ctx =
        CRYPTO_zalloc(core::mem::size_of::<OsslHpkeCtx>(), FILE_HPKE, 831).cast::<OsslHpkeCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is a fresh zeroed block this call owns.
    unsafe {
        (*ctx).libctx = libctx;
        (*ctx).mode = mode;
        (*ctx).suite = suite;
        (*ctx).kem_info = Some(kem_info);
        (*ctx).kdf_info = Some(kdf_info);
        (*ctx).aead_info = Some(aead_info);
        (*ctx).role = role;
    }
    if !propq.is_null() {
        // SAFETY: `propq` is NUL-terminated per the contract.
        let dup = unsafe { c_strdup(propq) };
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).propq = dup };
        if dup.is_null() {
            // The authority's `goto err` frees the cipher, the (NULL) propq and the context.
            // SAFETY: `ctx` is this call's own block and holds no other allocation yet.
            unsafe {
                EVP_CIPHER_free((*ctx).aead_ciph);
                CRYPTO_free((*ctx).propq.cast::<c_void>(), FILE_HPKE, 857);
                CRYPTO_free(ctx.cast::<c_void>(), FILE_HPKE, 858);
            }
            return ptr::null_mut();
        }
    }
    if suite.aead_id != OSSL_HPKE_AEAD_ID_EXPORTONLY {
        // SAFETY: `aead_info.name` is `Some` for every non-export-only AEAD.
        let name = aead_info.name.map_or(ptr::null(), |n| n.as_ptr());
        // SAFETY: `libctx` and `propq` are the caller's; `ctx` is live.
        let ciph = unsafe { EVP_CIPHER_fetch(libctx, name, (*ctx).propq) };
        if ciph.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_843) };
            // SAFETY: `ctx` is this call's own block and holds only `propq`.
            unsafe {
                EVP_CIPHER_free((*ctx).aead_ciph);
                CRYPTO_free((*ctx).propq.cast::<c_void>(), FILE_HPKE, 857);
                CRYPTO_free(ctx.cast::<c_void>(), FILE_HPKE, 858);
            }
            return ptr::null_mut();
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).aead_ciph = ciph };
    }
    ctx
}

/// `void OSSL_HPKE_CTX_free(OSSL_HPKE_CTX *ctx)` — `hpke.c:862`.
///
/// # Safety
/// `ctx` must be NULL or a live context this crate allocated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HPKE_CTX_free(ctx: *mut OsslHpkeCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the contract and every pointer is NULL or this crate's own.
    unsafe {
        EVP_CIPHER_free((*ctx).aead_ciph);
        CRYPTO_free((*ctx).propq.cast::<c_void>(), FILE_HPKE, 867);
        CRYPTO_clear_free(
            (*ctx).exportersec.cast::<c_void>(),
            (*ctx).exporterseclen,
            FILE_HPKE,
            868,
        );
        CRYPTO_free((*ctx).pskid.cast::<c_void>(), FILE_HPKE, 869);
        CRYPTO_clear_free((*ctx).psk.cast::<c_void>(), (*ctx).psklen, FILE_HPKE, 870);
        CRYPTO_clear_free((*ctx).key.cast::<c_void>(), (*ctx).keylen, FILE_HPKE, 871);
        CRYPTO_clear_free(
            (*ctx).nonce.cast::<c_void>(),
            (*ctx).noncelen,
            FILE_HPKE,
            872,
        );
        CRYPTO_clear_free(
            (*ctx).shared_secret.cast::<c_void>(),
            (*ctx).shared_secretlen,
            FILE_HPKE,
            873,
        );
        CRYPTO_clear_free((*ctx).ikme.cast::<c_void>(), (*ctx).ikmelen, FILE_HPKE, 874);
        EVP_PKEY_free((*ctx).authpriv);
        CRYPTO_free((*ctx).authpub.cast::<c_void>(), FILE_HPKE, 876);
        CRYPTO_free(ctx.cast::<c_void>(), FILE_HPKE, 878);
    }
}

/// `int OSSL_HPKE_CTX_set1_psk(OSSL_HPKE_CTX *ctx, const char *pskid,
///     const unsigned char *psk, size_t psklen)` — `hpke.c:882`.
///
/// Six validations in the authority's order: NULL arguments, a psk longer than the maximum, a psk
/// shorter than the minimum, a pskid past the maximum, an empty pskid, and a mode that is not a
/// PSK mode. Only then is the previous psk released and the new one taken.
///
/// # Safety
/// `ctx` NULL or live; `pskid` NULL or NUL-terminated; `psk` NULL or readable for `psklen`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HPKE_CTX_set1_psk(
    ctx: *mut OsslHpkeCtx,
    pskid: *const c_char,
    psk: *const c_uchar,
    psklen: usize,
) -> c_int {
    if ctx.is_null() || pskid.is_null() || psk.is_null() || psklen == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_887) };
        return 0;
    }
    if psklen > OSSL_HPKE_MAX_PARMLEN {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_891) };
        return 0;
    }
    if psklen < OSSL_HPKE_MIN_PSKLEN {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_895) };
        return 0;
    }
    // SAFETY: `pskid` is NUL-terminated per the contract.
    if unsafe { c_strnlen(pskid, usize::MAX) } > OSSL_HPKE_MAX_PARMLEN {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_899) };
        return 0;
    }
    // SAFETY: `pskid` is NUL-terminated.
    if unsafe { *pskid } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_903) };
        return 0;
    }
    // SAFETY: `ctx` is live on this arm.
    let mode = unsafe { (*ctx).mode };
    if mode != OSSL_HPKE_MODE_PSK && mode != OSSL_HPKE_MODE_PSKAUTH {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_908) };
        return 0;
    }
    // Free previous values if any.
    // SAFETY: `ctx` is live and `psk` is NULL or this crate's own block.
    unsafe { CRYPTO_clear_free((*ctx).psk.cast::<c_void>(), (*ctx).psklen, FILE_HPKE, 912) };
    // SAFETY: `psk` is readable for `psklen` per the contract.
    let dup = unsafe { c_memdup(psk, psklen) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).psk = dup };
    if dup.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).psklen = psklen;
        CRYPTO_free((*ctx).pskid.cast::<c_void>(), FILE_HPKE, 917);
    }
    // SAFETY: `pskid` is NUL-terminated.
    let id = unsafe { c_strdup(pskid) };
    if id.is_null() {
        // SAFETY: `ctx` is live and `psk` is this call's own block.
        unsafe {
            CRYPTO_clear_free((*ctx).psk.cast::<c_void>(), (*ctx).psklen, FILE_HPKE, 920);
            (*ctx).psk = ptr::null_mut();
            (*ctx).psklen = 0;
        }
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).pskid = id };
    1
}

/// `int OSSL_HPKE_CTX_set1_ikme(OSSL_HPKE_CTX *ctx, const unsigned char *ikme,
///     size_t ikmelen)` — `hpke.c:928`.
///
/// The sender's deterministic-keygen IKM, so a receiver role is refused. The NULL pair raises
/// `PASSED_NULL_PARAMETER` and the empty/oversize ikme raises `PASSED_INVALID_ARGUMENT` — two
/// different reasons for two different classes of bad input.
///
/// # Safety
/// `ctx` NULL or live; `ikme` NULL or readable for `ikmelen`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HPKE_CTX_set1_ikme(
    ctx: *mut OsslHpkeCtx,
    ikme: *const c_uchar,
    ikmelen: usize,
) -> c_int {
    if ctx.is_null() || ikme.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_932) };
        return 0;
    }
    if ikmelen == 0 || ikmelen > OSSL_HPKE_MAX_PARMLEN {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_936) };
        return 0;
    }
    // SAFETY: `ctx` is live on this arm.
    if unsafe { (*ctx).role } != OSSL_HPKE_ROLE_SENDER {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_940) };
        return 0;
    }
    // SAFETY: `ctx` is live and `ikme` is NULL or this crate's own block.
    unsafe { CRYPTO_clear_free((*ctx).ikme.cast::<c_void>(), (*ctx).ikmelen, FILE_HPKE, 943) };
    // SAFETY: `ikme` is readable for `ikmelen` per the contract.
    let dup = unsafe { c_memdup(ikme, ikmelen) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).ikme = dup };
    if dup.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).ikmelen = ikmelen };
    1
}

/// `int OSSL_HPKE_CTX_set1_authpriv(OSSL_HPKE_CTX *ctx, EVP_PKEY *priv)` — `hpke.c:951`.
///
/// # Safety
/// `ctx` NULL or live; `priv` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HPKE_CTX_set1_authpriv(
    ctx: *mut OsslHpkeCtx,
    priv_: *mut EvpPkey,
) -> c_int {
    if ctx.is_null() || priv_.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_954) };
        return 0;
    }
    // SAFETY: `ctx` is live on this arm.
    let mode = unsafe { (*ctx).mode };
    if mode != OSSL_HPKE_MODE_AUTH && mode != OSSL_HPKE_MODE_PSKAUTH {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_959) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).role } != OSSL_HPKE_ROLE_SENDER {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_963) };
        return 0;
    }
    // SAFETY: `ctx` is live and `authpriv` is NULL or this crate's own key.
    unsafe { EVP_PKEY_free((*ctx).authpriv) };
    // SAFETY: `priv_` is live per the contract.
    let dup = unsafe { EVP_PKEY_dup(priv_) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).authpriv = dup };
    if dup.is_null() {
        return 0;
    }
    1
}

/// `int OSSL_HPKE_CTX_set1_authpub(OSSL_HPKE_CTX *ctx, const unsigned char *pub,
///     size_t publen)` — `hpke.c:973`.
///
/// Imports the peer's public value, re-exports it in canonical encoded form (so a compressed point
/// is normalised), and stores that. The receiver role is the only one that may set it.
///
/// # Safety
/// `ctx` NULL or live; `pub` NULL or readable for `publen`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HPKE_CTX_set1_authpub(
    ctx: *mut OsslHpkeCtx,
    pub_: *const c_uchar,
    publen: usize,
) -> c_int {
    let mut erv = 0;
    let mut lpublen: usize = 0;

    if ctx.is_null() || pub_.is_null() || publen == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_983) };
        return 0;
    }
    // SAFETY: `ctx` is live on this arm.
    let mode = unsafe { (*ctx).mode };
    if mode != OSSL_HPKE_MODE_AUTH && mode != OSSL_HPKE_MODE_PSKAUTH {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_988) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).role } != OSSL_HPKE_ROLE_RECEIVER {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_992) };
        return 0;
    }
    // Check the value seems like a good public key for this kem.
    // SAFETY: `ctx` is live.
    let Some(kem_info) = kem_info_find_id(unsafe { (*ctx).suite }.kem_id) else {
        return 0;
    };
    // SAFETY: `ctx` is live.
    let pubp: *mut EvpPkey = if hpke_kem_id_nist_curve(unsafe { (*ctx).suite }.kem_id) {
        // SAFETY: `ctx` is live; `groupname` is `Some` on this arm.
        let gname = kem_info.groupname.map_or(ptr::null(), |g| g.as_ptr());
        // SAFETY: forwarded under this function's contract.
        unsafe {
            evp_pkey_new_raw_nist_public_key((*ctx).libctx, (*ctx).propq, gname, pub_, publen)
        }
    } else {
        // SAFETY: `ctx` is live; `keytype` is NUL-terminated.
        unsafe {
            EVP_PKEY_new_raw_public_key_ex(
                (*ctx).libctx,
                kem_info.keytype.as_ptr(),
                (*ctx).propq,
                pub_,
                publen,
            )
        }
    };
    'body: {
        if pubp.is_null() {
            // Can happen based on external input -- the buffer value may be garbage.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_1011) };
            break 'body;
        }
        // SAFETY: `lpub` is a fresh 512-byte block.
        let lpub = CRYPTO_malloc(OSSL_HPKE_MAXSIZE, FILE_HPKE, 1018).cast::<c_uchar>();
        if lpub.is_null() {
            break 'body;
        }
        // SAFETY: `pubp` is live; `lpub` writable for 512 bytes.
        if unsafe {
            EVP_PKEY_get_octet_string_param(
                pubp,
                OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                lpub,
                OSSL_HPKE_MAXSIZE,
                &mut lpublen,
            )
        } != 1
        {
            // SAFETY: `lpub` is this call's own block.
            unsafe { CRYPTO_free(lpub.cast::<c_void>(), FILE_HPKE, 1025) };
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_1026) };
            break 'body;
        }
        // Free up old value.
        // SAFETY: `ctx` is live and `authpub` is NULL or this crate's own block.
        unsafe { CRYPTO_free((*ctx).authpub.cast::<c_void>(), FILE_HPKE, 1030) };
        // SAFETY: `ctx` is live.
        unsafe {
            (*ctx).authpub = lpub;
            (*ctx).authpublen = lpublen;
        }
        erv = 1;
    }
    // SAFETY: `pubp` is NULL or this call's own key.
    unsafe { EVP_PKEY_free(pubp) };
    erv
}

/// `int OSSL_HPKE_CTX_get_seq(OSSL_HPKE_CTX *ctx, uint64_t *seq)` — `hpke.c:1040`.
///
/// # Safety
/// `ctx` NULL or live; `seq` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HPKE_CTX_get_seq(ctx: *mut OsslHpkeCtx, seq: *mut u64) -> c_int {
    if ctx.is_null() || seq.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1043) };
        return 0;
    }
    // SAFETY: `ctx` and `seq` are live per the contract.
    unsafe { *seq = (*ctx).seq };
    1
}

/// `int OSSL_HPKE_CTX_set_seq(OSSL_HPKE_CTX *ctx, uint64_t seq)` — `hpke.c:1050`.
///
/// A sender may **not** set its sequence: the authority's comment says a sender getting it wrong is
/// dangerous while a receiver's is not. That is a role-dependent refusal the court drives.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HPKE_CTX_set_seq(ctx: *mut OsslHpkeCtx, seq: u64) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1053) };
        return 0;
    }
    // SAFETY: `ctx` is live on this arm.
    if unsafe { (*ctx).role } == OSSL_HPKE_ROLE_SENDER {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1062) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).seq = seq };
    1
}

/// `int OSSL_HPKE_encap(OSSL_HPKE_CTX *ctx, unsigned char *enc, size_t *enclen,
///     const unsigned char *pub, size_t publen, const unsigned char *info, size_t infolen)` —
/// `hpke.c:1069`.
///
/// # Safety
/// `ctx` NULL or live; `enc` writable for `*enclen`; `enclen` writable; `pub` readable for
/// `publen`; `info` readable for `infolen` unless 0.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HPKE_encap(
    ctx: *mut OsslHpkeCtx,
    enc: *mut c_uchar,
    enclen: *mut usize,
    pub_: *const c_uchar,
    publen: usize,
    info: *const c_uchar,
    infolen: usize,
) -> c_int {
    if ctx.is_null() || enc.is_null() || enclen.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1079) };
        return 0;
    }
    // SAFETY: `enclen` is a live out-parameter on this arm, the NULL case being refused above.
    if unsafe { *enclen } == 0 || pub_.is_null() || publen == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1079) };
        return 0;
    }
    // SAFETY: `ctx` is live on this arm.
    if unsafe { (*ctx).role } != OSSL_HPKE_ROLE_SENDER {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1083) };
        return 0;
    }
    if infolen > OSSL_HPKE_MAX_INFOLEN {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1087) };
        return 0;
    }
    if infolen > 0 && info.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1091) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    let minenc = unsafe { OSSL_HPKE_get_public_encap_size((*ctx).suite) };
    // SAFETY: `enclen` is a live out-parameter on this arm (NULL was refused above).
    if minenc == 0 || minenc > unsafe { *enclen } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1096) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).shared_secret }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1101) };
        return 0;
    }
    // SAFETY: `ctx` is live and the arguments are the caller's.
    if unsafe { hpke_encap(ctx, enc, enclen, pub_, publen) } != 1 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1105) };
        return 0;
    }
    // The info is not part of the context; it is used once here.
    // SAFETY: `ctx` is live and `info` is NULL-or-readable per the checks.
    unsafe { hpke_do_middle(ctx, info, infolen) }
}

/// `int OSSL_HPKE_decap(OSSL_HPKE_CTX *ctx, const unsigned char *enc, size_t enclen,
///     EVP_PKEY *recippriv, const unsigned char *info, size_t infolen)` — `hpke.c:1117`.
///
/// # Safety
/// `ctx` NULL or live; `enc` readable for `enclen`; `recippriv` NULL or live; `info` readable for
/// `infolen` unless 0.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HPKE_decap(
    ctx: *mut OsslHpkeCtx,
    enc: *const c_uchar,
    enclen: usize,
    recippriv: *mut EvpPkey,
    info: *const c_uchar,
    infolen: usize,
) -> c_int {
    if ctx.is_null() || enc.is_null() || enclen == 0 || recippriv.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1126) };
        return 0;
    }
    // SAFETY: `ctx` is live on this arm.
    if unsafe { (*ctx).role } != OSSL_HPKE_ROLE_RECEIVER {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1130) };
        return 0;
    }
    if infolen > OSSL_HPKE_MAX_INFOLEN {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1134) };
        return 0;
    }
    if infolen > 0 && info.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1138) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    let minenc = unsafe { OSSL_HPKE_get_public_encap_size((*ctx).suite) };
    if minenc == 0 || minenc > enclen {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1143) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).shared_secret }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1148) };
        return 0;
    }
    // SAFETY: `ctx`, `enc` and `recippriv` are the caller's under this function's contract.
    let erv = unsafe { hpke_decap(ctx, enc, enclen, recippriv) };
    if erv != 1 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1153) };
        return 0;
    }
    // SAFETY: `ctx` is live and `info` is NULL-or-readable per the checks.
    unsafe { hpke_do_middle(ctx, info, infolen) }
}

/// `int OSSL_HPKE_seal(OSSL_HPKE_CTX *ctx, unsigned char *ct, size_t *ctlen,
///     const unsigned char *aad, size_t aadlen, const unsigned char *pt, size_t ptlen)` —
/// `hpke.c:1165`.
///
/// # Safety
/// `ctx` NULL or live; `ct` writable for `*ctlen`; `ctlen` writable; `aad` readable for `aadlen`
/// unless 0; `pt` readable for `ptlen`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HPKE_seal(
    ctx: *mut OsslHpkeCtx,
    ct: *mut c_uchar,
    ctlen: *mut usize,
    aad: *const c_uchar,
    aadlen: usize,
    pt: *const c_uchar,
    ptlen: usize,
) -> c_int {
    let mut seqbuf = [0 as c_uchar; OSSL_HPKE_MAX_NONCELEN];

    if ctx.is_null() || ct.is_null() || ctlen.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1175) };
        return 0;
    }
    // SAFETY: `ctlen` is a live out-parameter on this arm, the NULL case being refused above.
    if unsafe { *ctlen } == 0 || pt.is_null() || ptlen == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1175) };
        return 0;
    }
    // SAFETY: `ctx` is live on this arm.
    if unsafe { (*ctx).role } != OSSL_HPKE_ROLE_SENDER {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1179) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).seq.wrapping_add(1) } == 0 {
        // Wrap around imminent.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1183) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).key }.is_null() || unsafe { (*ctx).nonce }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1188) };
        return 0;
    }
    // SAFETY: `ctx` is live; `seqbuf` is this frame's 12-byte buffer.
    let seqlen = unsafe { hpke_seqnonce2buf(ctx, seqbuf.as_mut_ptr(), seqbuf.len()) };
    if seqlen == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1193) };
        return 0;
    }
    // SAFETY: `ctx` is live and the arguments are the caller's under this function's contract.
    if unsafe { hpke_aead_enc(ctx, seqbuf.as_ptr(), aad, aadlen, pt, ptlen, ct, ctlen) } != 1 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1197) };
        // SAFETY: `seqbuf` is this frame's buffer.
        unsafe { cleanse_ptr(seqbuf.as_mut_ptr(), seqbuf.len()) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).seq = (*ctx).seq.wrapping_add(1) };
    // SAFETY: `seqbuf` is this frame's buffer.
    unsafe { cleanse_ptr(seqbuf.as_mut_ptr(), seqbuf.len()) };
    1
}

/// `int OSSL_HPKE_open(OSSL_HPKE_CTX *ctx, unsigned char *pt, size_t *ptlen,
///     const unsigned char *aad, size_t aadlen, const unsigned char *ct, size_t ctlen)` —
/// `hpke.c:1207`.
///
/// # Safety
/// `ctx` NULL or live; `pt` writable for `*ptlen`; `ptlen` writable; `aad` readable for `aadlen`
/// unless 0; `ct` readable for `ctlen`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HPKE_open(
    ctx: *mut OsslHpkeCtx,
    pt: *mut c_uchar,
    ptlen: *mut usize,
    aad: *const c_uchar,
    aadlen: usize,
    ct: *const c_uchar,
    ctlen: usize,
) -> c_int {
    let mut seqbuf = [0 as c_uchar; OSSL_HPKE_MAX_NONCELEN];

    if ctx.is_null() || pt.is_null() || ptlen.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1217) };
        return 0;
    }
    // SAFETY: `ptlen` is a live out-parameter on this arm, the NULL case being refused above.
    if unsafe { *ptlen } == 0 || ct.is_null() || ctlen == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1217) };
        return 0;
    }
    // SAFETY: `ctx` is live on this arm.
    if unsafe { (*ctx).role } != OSSL_HPKE_ROLE_RECEIVER {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1221) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).seq.wrapping_add(1) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1225) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).key }.is_null() || unsafe { (*ctx).nonce }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1230) };
        return 0;
    }
    // SAFETY: `ctx` is live; `seqbuf` is this frame's 12-byte buffer.
    let seqlen = unsafe { hpke_seqnonce2buf(ctx, seqbuf.as_mut_ptr(), seqbuf.len()) };
    if seqlen == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1235) };
        return 0;
    }
    // SAFETY: `ctx` is live and the arguments are the caller's under this function's contract.
    if unsafe { hpke_aead_dec(ctx, seqbuf.as_ptr(), aad, aadlen, ct, ctlen, pt, ptlen) } != 1 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1239) };
        // SAFETY: `seqbuf` is this frame's buffer.
        unsafe { cleanse_ptr(seqbuf.as_mut_ptr(), seqbuf.len()) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).seq = (*ctx).seq.wrapping_add(1) };
    // SAFETY: `seqbuf` is this frame's buffer.
    unsafe { cleanse_ptr(seqbuf.as_mut_ptr(), seqbuf.len()) };
    1
}

/// `int OSSL_HPKE_export(OSSL_HPKE_CTX *ctx, unsigned char *secret, size_t secretlen,
///     const unsigned char *label, size_t labellen)` — `hpke.c:1248`.
///
/// # Safety
/// `ctx` NULL or live; `secret` writable for `secretlen`; `label` readable for `labellen` unless 0.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HPKE_export(
    ctx: *mut OsslHpkeCtx,
    secret: *mut c_uchar,
    secretlen: usize,
    label: *const c_uchar,
    labellen: usize,
) -> c_int {
    let mut suitebuf = [0 as c_uchar; 6];

    if ctx.is_null() || secret.is_null() || secretlen == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1259) };
        return 0;
    }
    if labellen > OSSL_HPKE_MAX_PARMLEN {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1263) };
        return 0;
    }
    if labellen > 0 && label.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1267) };
        return 0;
    }
    // SAFETY: `ctx` is live on this arm.
    if unsafe { (*ctx).exportersec }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1271) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    let suite = unsafe { (*ctx).suite };
    let Some(kdf_info) = kdf_info_find_id(suite.kdf_id) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1276) };
        return 0;
    };
    // SAFETY: `ctx` is live; `mdname` is NUL-terminated.
    let kctx = unsafe {
        kdf_ctx_create(
            c"HKDF".as_ptr(),
            kdf_info.mdname.as_ptr(),
            (*ctx).libctx,
            (*ctx).propq,
        )
    };
    if kctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1282) };
        return 0;
    }
    // Full suiteid as per RFC9180 sec 5.3.
    suitebuf[0] = (suite.kem_id / 256) as c_uchar;
    suitebuf[1] = (suite.kem_id % 256) as c_uchar;
    suitebuf[2] = (suite.kdf_id / 256) as c_uchar;
    suitebuf[3] = (suite.kdf_id % 256) as c_uchar;
    suitebuf[4] = (suite.aead_id / 256) as c_uchar;
    suitebuf[5] = (suite.aead_id % 256) as c_uchar;
    // SAFETY: `kctx` is live; `secret` writable for `secretlen`; `label` NULL-or-readable.
    let erv = unsafe {
        hpke_labeled_expand(
            kctx,
            secret,
            secretlen,
            (*ctx).exportersec,
            (*ctx).exporterseclen,
            SEC51LABEL,
            suitebuf.as_ptr(),
            suitebuf.len(),
            EXP_SEC_LABEL,
            label,
            labellen,
        )
    };
    // SAFETY: `kctx` is this call's own context.
    unsafe { EVP_KDF_CTX_free(kctx) };
    if erv != 1 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1300) };
    }
    erv
}

/// `int OSSL_HPKE_keygen(OSSL_HPKE_SUITE suite, unsigned char *pub, size_t *publen,
///     EVP_PKEY **priv, const unsigned char *ikm, size_t ikmlen, OSSL_LIB_CTX *libctx,
///     const char *propq)` — `hpke.c:1304`.
///
/// The `ikmlen`/`ikm` consistency test is the one worth naming: **both** a non-zero length with a
/// NULL buffer and a non-NULL buffer with a zero length are refused.
///
/// # Safety
/// `pub` writable for `*publen`; `publen` writable; `priv` writable for one pointer; `ikm` NULL or
/// readable for `ikmlen`; `libctx` NULL or live; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HPKE_keygen(
    suite: OsslHpkeSuite,
    pub_: *mut c_uchar,
    publen: *mut usize,
    priv_: *mut *mut EvpPkey,
    ikm: *const c_uchar,
    ikmlen: usize,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut erv = 0;
    let mut params: [OsslParam; 3] = [OSSL_PARAM_construct_end(); 3];
    let mut p = 0usize;
    let mut skr: *mut EvpPkey = ptr::null_mut();

    // SAFETY: `publen` is a live out-parameter on this arm, the NULL case being part of the guard.
    if pub_.is_null() || publen.is_null() || unsafe { *publen } == 0 || priv_.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1316) };
        return 0;
    }
    let Some((kem_info, _kdf_info, _aead_info)) = hpke_suite_check(suite) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1320) };
        return 0;
    };
    if (ikmlen > 0 && ikm.is_null())
        || (ikmlen == 0 && !ikm.is_null())
        || ikmlen > OSSL_HPKE_MAX_PARMLEN
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::HPKE_1326) };
        return 0;
    }

    // SAFETY: forwarded under this function's contract.
    let mut pctx: *mut EvpPkeyCtx = if hpke_kem_id_nist_curve(suite.kem_id) {
        // SAFETY: one constructor writes one entry and the array has three; `groupname` is `Some`.
        unsafe {
            params[p] = OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_GROUP_NAME,
                kem_info
                    .groupname
                    .map_or(ptr::null_mut(), |g| g.as_ptr().cast_mut()),
                0,
            );
        }
        p += 1;
        // SAFETY: forwarded under this function's contract; `libctx` and `propq` are the
        // caller's and the `EC` literal is NUL-terminated.
        unsafe { EVP_PKEY_CTX_new_from_name(libctx, c"EC".as_ptr(), propq) }
    } else {
        // SAFETY: `keytype` is NUL-terminated.
        unsafe { EVP_PKEY_CTX_new_from_name(libctx, kem_info.keytype.as_ptr(), propq) }
    };
    'body: {
        // SAFETY: `pctx` is NULL or live; both calls accept that.
        if pctx.is_null() || unsafe { EVP_PKEY_keygen_init(pctx) } <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_1339) };
            break 'body;
        }
        if !ikm.is_null() {
            // SAFETY: one constructor writes one entry and `p` is at most 1 here.
            unsafe {
                params[p] = OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_DHKEM_IKM,
                    ikm.cast_mut().cast::<c_void>(),
                    ikmlen,
                );
            }
            p += 1;
        }
        // SAFETY: `p` is at most 2 and the array has three.
        params[p] = OSSL_PARAM_construct_end();
        // SAFETY: `pctx` is live and `params` is terminated.
        if unsafe { EVP_PKEY_CTX_set_params(pctx, params.as_ptr()) } <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_1347) };
            break 'body;
        }
        // SAFETY: `pctx` is live and `skr` is writable for one pointer.
        if unsafe { EVP_PKEY_generate(pctx, &mut skr) } <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_1351) };
            break 'body;
        }
        // SAFETY: `pctx` is this call's own context.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        pctx = ptr::null_mut();
        // SAFETY: `skr` is live; `pub_` is writable for `*publen`.
        if unsafe {
            EVP_PKEY_get_octet_string_param(
                skr,
                OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                pub_,
                *publen,
                publen,
            )
        } != 1
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::HPKE_1359) };
            break 'body;
        }
        // SAFETY: `priv_` is writable for one pointer per the contract.
        unsafe { *priv_ = skr };
        erv = 1;
    }
    if erv != 1 {
        // SAFETY: `skr` is NULL or this call's own key.
        unsafe { EVP_PKEY_free(skr) };
    }
    // SAFETY: `pctx` is NULL here or this call's own context.
    unsafe { EVP_PKEY_CTX_free(pctx) };
    erv
}

/// `int OSSL_HPKE_suite_check(OSSL_HPKE_SUITE suite)` — `hpke.c:1372`.
#[no_mangle]
pub extern "C" fn OSSL_HPKE_suite_check(suite: OsslHpkeSuite) -> c_int {
    c_int::from(hpke_suite_check(suite).is_some())
}

/// `int OSSL_HPKE_str2suite(const char *str, OSSL_HPKE_SUITE *suite)` — `hpke.c:1442`.
///
/// # Safety
/// `str` NULL or NUL-terminated; `suite` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HPKE_str2suite(
    str_: *const c_char,
    suite: *mut OsslHpkeSuite,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe { hpke_str2suite(str_, suite) }
}

/// `size_t OSSL_HPKE_get_ciphertext_size(OSSL_HPKE_SUITE suite, size_t clearlen)` —
/// `hpke.c:1447`.
#[no_mangle]
pub extern "C" fn OSSL_HPKE_get_ciphertext_size(suite: OsslHpkeSuite, clearlen: usize) -> usize {
    match hpke_expansion(suite, clearlen) {
        Some((_enclen, cipherlen)) => cipherlen,
        None => 0,
    }
}

/// `size_t OSSL_HPKE_get_public_encap_size(OSSL_HPKE_SUITE suite)` — `hpke.c:1457`.
#[no_mangle]
pub extern "C" fn OSSL_HPKE_get_public_encap_size(suite: OsslHpkeSuite) -> usize {
    match hpke_expansion(suite, 16) {
        Some((enclen, _cipherlen)) => enclen,
        None => 0,
    }
}

/// `size_t OSSL_HPKE_get_recommended_ikmelen(OSSL_HPKE_SUITE suite)` — `hpke.c:1468`.
#[no_mangle]
pub extern "C" fn OSSL_HPKE_get_recommended_ikmelen(suite: OsslHpkeSuite) -> usize {
    match hpke_suite_check(suite) {
        Some((kem_info, _kdf_info, _aead_info)) => kem_info.nsk,
        None => 0,
    }
}

/// `OPENSSL_memdup(p, len)` — a copy of `len` bytes, or NULL.
///
/// # Safety
/// `p` must be readable for `len` bytes.
unsafe fn c_memdup(p: *const c_uchar, len: usize) -> *mut c_uchar {
    let out = CRYPTO_malloc(len, FILE_HPKE_UTIL, 483).cast::<c_uchar>();
    if out.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `out` is `len` bytes and `p` is readable for `len` per the contract.
    unsafe { ptr::copy_nonoverlapping(p, out, len) };
    out
}

/// `OPENSSL_strdup(s)` — a copy of the NUL-terminated string including its terminator, or NULL.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn c_strdup(s: *const c_char) -> *mut c_char {
    // SAFETY: `s` is NUL-terminated per the contract.
    let len = unsafe { c_strnlen(s, usize::MAX) };
    let out = CRYPTO_malloc(len + 1, FILE_HPKE, 836).cast::<c_char>();
    if out.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `out` is `len + 1` bytes and `s` is readable for `len + 1` (the terminator included).
    unsafe {
        ptr::copy_nonoverlapping(s, out, len);
        *out.add(len) = 0;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suite(kem: u16, kdf: u16, aead: u16) -> OsslHpkeSuite {
        OsslHpkeSuite {
            kem_id: kem,
            kdf_id: kdf,
            aead_id: aead,
        }
    }

    /// The suite lookups and the size arithmetic are drivable without a provider, and they are the
    /// part of the surface a court can compare exactly.
    #[test]
    fn suite_check_and_sizes_agree_with_the_tables() {
        let x25519 = suite(
            OSSL_HPKE_KEM_ID_X25519,
            OSSL_HPKE_KDF_ID_HKDF_SHA256,
            OSSL_HPKE_AEAD_ID_AES_GCM_128,
        );
        assert_eq!(OSSL_HPKE_suite_check(x25519), 1);
        assert_eq!(OSSL_HPKE_get_public_encap_size(x25519), X25519_KEYLEN);
        assert_eq!(OSSL_HPKE_get_ciphertext_size(x25519, 32), 32 + 16);
        assert_eq!(OSSL_HPKE_get_recommended_ikmelen(x25519), X25519_KEYLEN);
        let p256 = suite(
            OSSL_HPKE_KEM_ID_P256,
            OSSL_HPKE_KDF_ID_HKDF_SHA384,
            OSSL_HPKE_AEAD_ID_CHACHA_POLY1305,
        );
        assert_eq!(OSSL_HPKE_suite_check(p256), 1);
        assert_eq!(OSSL_HPKE_get_public_encap_size(p256), 65);
        // A reserved KEM id is a miss, and a miss is 0.
        let bad = suite(
            0,
            OSSL_HPKE_KDF_ID_HKDF_SHA256,
            OSSL_HPKE_AEAD_ID_AES_GCM_128,
        );
        assert_eq!(OSSL_HPKE_suite_check(bad), 0);
        assert_eq!(OSSL_HPKE_get_public_encap_size(bad), 0);
    }

    /// `str2suite`'s silent refusals and its successes, including the export-only pseudo-AEAD
    /// whose synonym is the literal `"exporter"`.
    #[test]
    fn str2suite_parses_names_and_numbers() {
        let mut s = suite(0, 0, 0);
        // SAFETY: `s` is this test's own suite and the literal is NUL-terminated.
        let rv = unsafe { OSSL_HPKE_str2suite(c"X25519,0x1,aes-128-gcm".as_ptr(), &mut s) };
        assert_eq!(rv, 1);
        assert_eq!(s.kem_id, OSSL_HPKE_KEM_ID_X25519);
        assert_eq!(s.kdf_id, OSSL_HPKE_KDF_ID_HKDF_SHA256);
        assert_eq!(s.aead_id, OSSL_HPKE_AEAD_ID_AES_GCM_128);
        // The export-only aead, by its synonym.
        // SAFETY: as above; `s` is this test's own suite.
        let rv = unsafe { OSSL_HPKE_str2suite(c"P-256,hkdf-sha512,exporter".as_ptr(), &mut s) };
        assert_eq!(rv, 1);
        assert_eq!(s.aead_id, OSSL_HPKE_AEAD_ID_EXPORTONLY);
        // A delimiter at the end is a silent 0.
        // SAFETY: as above; `s` is this test's own suite.
        let rv = unsafe { OSSL_HPKE_str2suite(c"X25519,1,1,".as_ptr(), &mut s) };
        assert_eq!(rv, 0);
        // The wrong delimiter count is a silent 0.
        // SAFETY: as above; `s` is this test's own suite.
        let rv = unsafe { OSSL_HPKE_str2suite(c"X25519,1".as_ptr(), &mut s) };
        assert_eq!(rv, 0);
        // The empty prefix is a refusal with a reason.
        // SAFETY: as above; `s` is this test's own suite.
        let rv = unsafe { OSSL_HPKE_str2suite(c"".as_ptr(), &mut s) };
        assert_eq!(rv, 0);
    }

    /// The mode and role refusals of `CTX_new`, which need no provider because they precede the
    /// AEAD fetch. The export-only suite fetches no cipher at all.
    #[test]
    fn ctx_new_validates_mode_suite_and_role() {
        let export_only = suite(
            OSSL_HPKE_KEM_ID_X25519,
            OSSL_HPKE_KDF_ID_HKDF_SHA256,
            OSSL_HPKE_AEAD_ID_EXPORTONLY,
        );
        // A bad mode is refused before the suite is even looked at.
        // SAFETY: the literal suite is a value and the two pointers are the NULL the function
        // documents.
        let p = unsafe { OSSL_HPKE_CTX_new(99, export_only, 0, ptr::null_mut(), ptr::null()) };
        assert!(p.is_null());
        // A bad role is refused after the suite check.
        // SAFETY: as above.
        let p = unsafe { OSSL_HPKE_CTX_new(0, export_only, 7, ptr::null_mut(), ptr::null()) };
        assert!(p.is_null());
        // The export-only suite succeeds without a provider.
        // SAFETY: as above; the caller owns the returned context.
        let ctx = unsafe {
            OSSL_HPKE_CTX_new(
                0,
                export_only,
                OSSL_HPKE_ROLE_SENDER,
                ptr::null_mut(),
                ptr::null(),
            )
        };
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is the live context just built.
        unsafe {
            let mut v: u64 = 0;
            assert_eq!(OSSL_HPKE_CTX_get_seq(ctx, &mut v), 1);
            assert_eq!(v, 0);
            // A sender may not set its sequence number.
            assert_eq!(OSSL_HPKE_CTX_set_seq(ctx, 1), 0);
            OSSL_HPKE_CTX_free(ctx);
        }
        // SAFETY: the literal suite is a value and the two pointers are the NULL the function
        // documents; the caller owns the returned context.
        let rctx = unsafe {
            OSSL_HPKE_CTX_new(
                0,
                export_only,
                OSSL_HPKE_ROLE_RECEIVER,
                ptr::null_mut(),
                ptr::null(),
            )
        };
        assert!(!rctx.is_null());
        // SAFETY: `rctx` is the live context just built.
        unsafe {
            assert_eq!(OSSL_HPKE_CTX_set_seq(rctx, 5), 1);
            let mut v: u64 = 0;
            assert_eq!(OSSL_HPKE_CTX_get_seq(rctx, &mut v), 1);
            assert_eq!(v, 5);
            OSSL_HPKE_CTX_free(rctx);
            // NULL handling on the free boundary and the two sequence accessors.
            OSSL_HPKE_CTX_free(ptr::null_mut());
            assert_eq!(OSSL_HPKE_CTX_get_seq(ptr::null_mut(), ptr::null_mut()), 0);
            assert_eq!(OSSL_HPKE_CTX_set_seq(ptr::null_mut(), 0), 0);
        }
    }
}
