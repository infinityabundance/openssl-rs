//! Phase 9 — the default provider's **GCM** cipher engine.
//!
//! `EVP_CIPHER_fetch(NULL, "AES-128-GCM", NULL)` resolves through the default provider's
//! `OSSL_OP_CIPHER` query to the `ossl_aes128gcm_functions` table this module publishes. The
//! tables land here rather than in `src/provider/cipher.rs` (the CCM landing, D238) because the
//! three arms that held these rows — the no-IV encrypting path (`ciphercommon_gcm.c.in:414-428`),
//! the TLS-AAD fixed-IV path (`:519-543`) and the TLS record path (`:551-612`) — draw bytes from
//! the random layer, which is Phase 9's and now exists (`src/rand/rand_lib.rs`'s `RAND_bytes_ex`).
//!
//! ## The seven rows
//!
//! `deflt_ciphers[]`'s `AES-128/192/256-GCM` (`providers/defltprov.c:202-204`),
//! `ARIA-128/192/256-GCM` (`:247-249`) and `SM4-GCM` (`:315`). The **engine** is one unit shared
//! by all seven — `ciphercommon_gcm.c.in`'s `ossl_gcm_*` functions and `ciphercommon_gcm_hw.c`'s
//! five hardware methods — and each row differs only in its key size and its per-algorithm `hw`
//! table, exactly as the CCM rows differ (D238's `ccm_row!`). That is what makes one `gcm_row!`
//! macro the honest expansion of `prov/ciphercommon_aead.h:18-67`'s `IMPLEMENT_aead_cipher`.
//!
//! ## The hardware arm this profile compiles
//!
//! `cipher_aes_gcm_hw.c` and `cipher_sm4_gcm_hw.c` each select an assembly `initkey`/`cipher_update`
//! through a capability test (`HWAES_CAPABLE`, `AESNI_CAPABLE`, `HWSM4_CAPABLE_X86_64`,
//! `VPSM4*_CAPABLE`) and **include** the selected `.inc` file; the C table is what remains when none
//! matches (`cipher_aes_gcm_hw.c:126-133`, `cipher_sm4_gcm_hw.c:277-284`). This crate declines the
//! assembly arms — the same decision D266 and D269 record for SM4 and AES generally — and
//! `ossl_prov_aes_hw_gcm`/`ossl_prov_sm4_hw_gcm` answer the C tables. ARIA has no assembly arm.
//! The consequence for `ctr` is measured, not assumed: `AES_CTR_ASM` is defined only for
//! `s390x` and `c64xplus` (`crypto/aes/build.info:30,55`), so on this host the C `initkey` installs
//! `ctx->ctr = NULL` and the `_ctr32` cipher-update branch is never taken. The branch is transcribed
//! anyway, because it is part of the C body and the crate's `_ctr32` entry points accept its
//! `ctr128_f`.
//!
//! ## What is deliberately not transcribed
//!
//! Nothing in `ciphercommon_gcm.c.in` is dropped. The `PROV_GCM_CTX` fields `mode`, `num`, `bufsz`
//! and `flags` are written nowhere and read nowhere in the GCM engine the authority ships; they are
//! present here only because they are bytes of the allocation request. `pad` is set by
//! `ossl_gcm_initctx` and never read, as in the authority.
//!
//! ## Measured layout
//!
//! `struct gcm128_context` in this crate (`src/modes/gcm.rs`) is a **compact** model of the
//! authority's `GCM128_CONTEXT` — D225 chose the standard big-endian field representation over the
//! Shoup table — so the provider context does not reproduce the authority's internal member
//! offsets for the embedded GCM state. The allocation **size**, which is what a caller's
//! `CRYPTO_set_mem_functions` receives as `num`, is still contract, and the numbers asserted in this
//! module's test were measured by a program compiled against the pinned build's internal headers
//! with `courts/layout/README.md`'s include set:
//!
//! ```text
//! sizeof(PROV_GCM_CTX)      = 704      sizeof(GCM128_CONTEXT) = 448
//! sizeof(PROV_AES_GCM_CTX)  = 960      sizeof(PROV_GCM_HW)    = 48
//! sizeof(PROV_ARIA_GCM_CTX) = 984      sizeof(PROV_SM4_GCM_CTX) = 832
//! offsetof(PROV_GCM_CTX, iv) = 85   (the five `unsigned int : 1` bits occupy one byte)
//! offsetof(PROV_GCM_CTX, buf) = 213  offsetof(PROV_GCM_CTX, libctx) = 232
//! offsetof(PROV_GCM_CTX, hw) = 240   offsetof(PROV_GCM_CTX, gcm) = 248
//! offsetof(PROV_GCM_CTX, ctr) = 696  offsetof(*_GCM_CTX, ks) = 704
//! ```
//!
//! `PROV_GCM_CTX` is reproduced at exactly **704** bytes: the crate's 152-byte `GcmCtx` carries its
//! `H`/`Xi` field elements as `[u64; 2]` rather than `u128`, so it has the authority's own
//! eight-byte alignment and sits at the authority's `gcm` offset of 248; a named reserve carries
//! the remaining 296 bytes to the region's end at 696, and `ctr` follows at the authority's own
//! offset 696. Every per-cipher context then matches the authority as well: `PROV_AES_GCM_CTX`
//! (960), `PROV_SM4_GCM_CTX` (832) and `PROV_ARIA_GCM_CTX` (984), with `ks` at 704.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void, CStr};
use core::ptr;

use crate::aes::{AES_encrypt, AES_set_encrypt_key, AesKey};
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::cipher::{
    OSSL_FUNC_CIPHER_CIPHER, OSSL_FUNC_CIPHER_DECRYPT_INIT, OSSL_FUNC_CIPHER_DUPCTX,
    OSSL_FUNC_CIPHER_ENCRYPT_INIT, OSSL_FUNC_CIPHER_FINAL, OSSL_FUNC_CIPHER_FREECTX,
    OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
    OSSL_FUNC_CIPHER_GET_CTX_PARAMS, OSSL_FUNC_CIPHER_GET_PARAMS, OSSL_FUNC_CIPHER_NEWCTX,
    OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, OSSL_FUNC_CIPHER_SET_CTX_PARAMS, OSSL_FUNC_CIPHER_UPDATE,
};
use crate::modes::gcm::{
    CRYPTO_gcm128_aad, CRYPTO_gcm128_decrypt, CRYPTO_gcm128_decrypt_ctr32, CRYPTO_gcm128_encrypt,
    CRYPTO_gcm128_encrypt_ctr32, CRYPTO_gcm128_finish, CRYPTO_gcm128_init, CRYPTO_gcm128_setiv,
    CRYPTO_gcm128_tag, GcmCtx,
};
use crate::modes::{Block128F, Ctr128F};
use crate::params::{
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_size_t, OSSL_PARAM_locate, OSSL_PARAM_locate_const,
    OSSL_PARAM_set_octet_string, OSSL_PARAM_set_octet_string_or_ptr, OSSL_PARAM_set_size_t,
    OSSL_PARAM_set_uint, OsslParam, END, OSSL_PARAM_OCTET_STRING,
};
use crate::provider::cipher::{
    ossl_cipher_generic_get_params, ossl_cipher_generic_gettable_params, param_octet_string,
    param_size_t, param_uint, repeated_param_site, AesKeyUnion,
};
use crate::provider::ctx::prov_libctx_of;
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_memdup, CRYPTO_zalloc, OPENSSL_cleanse};

/// `ERR_LIB_PROV` — `include/openssl/proverr.h`.
const ERR_LIB_PROV: c_int = 57;

/// `EVP_CIPH_GCM_MODE` — `include/openssl/evp.h:318`. The one mode the seven rows publish.
const EVP_CIPH_GCM_MODE: c_uint = 0x6;

/// `GCM_IV_DEFAULT_SIZE` — `prov/ciphercommon_gcm.h:20`.
const GCM_IV_DEFAULT_SIZE: usize = 12;
/// `GCM_IV_MAX_SIZE` — `prov/ciphercommon_gcm.h:21`.
const GCM_IV_MAX_SIZE: usize = 1024 / 8;
/// `GCM_TAG_MAX_SIZE` — `prov/ciphercommon_gcm.h:22`.
const GCM_TAG_MAX_SIZE: usize = 16;
/// `GENERIC_BLOCK_SIZE` — the size of `PROV_GCM_CTX`'s `buf`, `ciphercommon_gcm.h:76`.
const GCM_BLOCK_SIZE: usize = 16;

/// `EVP_GCM_TLS_FIXED_IV_LEN` — `include/openssl/evp.h:472`.
const EVP_GCM_TLS_FIXED_IV_LEN: usize = 4;
/// `EVP_GCM_TLS_EXPLICIT_IV_LEN` — `include/openssl/evp.h:474`.
const EVP_GCM_TLS_EXPLICIT_IV_LEN: usize = 8;
/// `EVP_GCM_TLS_TAG_LEN` — `include/openssl/evp.h:476`.
const EVP_GCM_TLS_TAG_LEN: usize = 16;
/// `EVP_AEAD_TLS1_AAD_LEN` — `include/openssl/evp.h:461`.
const EVP_AEAD_TLS1_AAD_LEN: usize = 13;

/// `UNINITIALISED_SIZET` — `prov/ciphercommon_aead.h:14`.
const UNINITIALISED_SIZET: usize = usize::MAX;

/// The GCM rows' `blkbits` — the sixth argument of every `IMPLEMENT_aead_cipher(..., gcm, GCM, ...)`.
const GCM_BLOCK_BITS: usize = 8;
/// The GCM rows' `ivbits` — the seventh argument of the same invocations.
const GCM_IV_BITS: usize = 96;

/// `AEAD_FLAGS` — `prov/ciphercommon_aead.h:16`, the flag pair every `IMPLEMENT_aead_cipher` row
/// passes: `PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV`.
const AEAD_FLAGS: u64 = PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV;
/// `PROV_CIPHER_FLAG_AEAD` — `prov/ciphercommon.h:22`.
const PROV_CIPHER_FLAG_AEAD: u64 = 0x0001;
/// `PROV_CIPHER_FLAG_CUSTOM_IV` — `prov/ciphercommon.h:23`.
const PROV_CIPHER_FLAG_CUSTOM_IV: u64 = 0x0002;

/// `IV_STATE_UNINITIALISED` — `prov/ciphercommon_gcm.h`'s `EVP_IV_STATE_*` family.
const IV_STATE_UNINITIALISED: c_uint = 0;
/// `IV_STATE_BUFFERED`.
const IV_STATE_BUFFERED: c_uint = 1;
/// `IV_STATE_COPIED`.
const IV_STATE_COPIED: c_uint = 2;
/// `IV_STATE_FINISHED`.
const IV_STATE_FINISHED: c_uint = 3;

// The parameter names the two generated decoders and the get/set lists use, each verbatim from
// `core_names.h` (`OSSL_CIPHER_PARAM_AEAD_IVLEN` is an alias of `OSSL_CIPHER_PARAM_IVLEN`).
/// `OSSL_CIPHER_PARAM_IVLEN` — `core_names.h:199` (`"ivlen"`).
const OSSL_CIPHER_PARAM_IVLEN: *const c_char = c"ivlen".as_ptr();
/// `OSSL_CIPHER_PARAM_KEYLEN` — `core_names.h:200` (`"keylen"`).
const OSSL_CIPHER_PARAM_KEYLEN: *const c_char = c"keylen".as_ptr();
/// `OSSL_CIPHER_PARAM_IV` — `core_names.h:198` (`"iv"`).
const OSSL_CIPHER_PARAM_IV: *const c_char = c"iv".as_ptr();
/// `OSSL_CIPHER_PARAM_UPDATED_IV` — `core_names.h:221` (`"updated-iv"`).
const OSSL_CIPHER_PARAM_UPDATED_IV: *const c_char = c"updated-iv".as_ptr();
/// `OSSL_CIPHER_PARAM_AEAD_TAG` — `core_names.h:179` (`"tag"`).
const OSSL_CIPHER_PARAM_AEAD_TAG: *const c_char = c"tag".as_ptr();
/// `OSSL_CIPHER_PARAM_AEAD_TAGLEN` — `core_names.h:180` (`"taglen"`).
const OSSL_CIPHER_PARAM_AEAD_TAGLEN: *const c_char = c"taglen".as_ptr();
/// `OSSL_CIPHER_PARAM_AEAD_TLS1_AAD` — `core_names.h:181` (`"tlsaad"`).
const OSSL_CIPHER_PARAM_AEAD_TLS1_AAD: *const c_char = c"tlsaad".as_ptr();
/// `OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD` — `core_names.h:182` (`"tlsaadpad"`).
const OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD: *const c_char = c"tlsaadpad".as_ptr();
/// `OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN` — `core_names.h:183` (`"tlsivgen"`).
const OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN: *const c_char = c"tlsivgen".as_ptr();
/// `OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED` — `core_names.h:184` (`"tlsivfixed"`).
const OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED: *const c_char = c"tlsivfixed".as_ptr();
/// `OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV` — `core_names.h:185` (`"tlsivinv"`).
const OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV: *const c_char = c"tlsivinv".as_ptr();
/// `OSSL_CIPHER_PARAM_AEAD_IV_GENERATED` — `core_names.h:177` (`"iv-generated"`).
const OSSL_CIPHER_PARAM_AEAD_IV_GENERATED: *const c_char = c"iv-generated".as_ptr();

/// The allocation-tracking `file` argument for the AES-GCM row's allocations: `cipher_aes_gcm.c`,
/// a source-tree file, so its `__FILE__` carries the build's `../../src/openssl-3.6.4/` prefix.
const FILE_AES_GCM: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_gcm.c".as_ptr();
/// The allocation-tracking `file` argument for the ARIA-GCM rows' allocations.
const FILE_ARIA_GCM: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aria_gcm.c".as_ptr();
/// The allocation-tracking `file` argument for the SM4-GCM row's allocation.
const FILE_SM4_GCM: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_sm4_gcm.c".as_ptr();

// ---------------------------------------------------------------------------------------------
// The engine's recorded raise coordinates
// ---------------------------------------------------------------------------------------------
//
// `ciphercommon_gcm.c` is generated from `ciphercommon_gcm.c.in`, so its `__FILE__` is the
// build-relative path with no `../../src/openssl-3.6.4/` prefix, exactly as the CCM sites are
// (`src/runtime/err_sites.rs`'s `PROV_CIPHERCOMMON_CCM_*`). The lines are the *generated* file's
// own, read from `forensics/authorities/build/openssl-3.6.4-production/.../ciphercommon_gcm.c`
// because the `.in` template's line numbers are not the compiled ones — the generated decoders add
// roughly 270 lines ahead of the get/set bodies. `src/runtime/err_sites.rs` is generated and does
// not yet carry these coordinates, so they are declared here, under the generator's own naming;
// they belong in `err_sites.rs` once that generator next runs.

/// One `ciphercommon_gcm.c` raise coordinate. `line` and `func` are the generated file's own.
const fn gcm_site(line: c_int, func: &'static CStr, reason: c_int) -> err_sites::ErrSite {
    err_sites::ErrSite {
        file: c"providers/implementations/ciphers/ciphercommon_gcm.c",
        line,
        func,
        lib: ERR_LIB_PROV,
        reason,
        dynamic_reason: false,
    }
}

/// `PROV_R_CIPHER_OPERATION_FAILED` — `include/openssl/proverr.h` (102).
const PROV_R_CIPHER_OPERATION_FAILED: c_int = 102;
/// `PROV_R_FAILED_TO_GET_PARAMETER` (103).
const PROV_R_FAILED_TO_GET_PARAMETER: c_int = 103;
/// `PROV_R_FAILED_TO_SET_PARAMETER` (104).
const PROV_R_FAILED_TO_SET_PARAMETER: c_int = 104;
/// `PROV_R_INVALID_KEY_LENGTH` (105).
const PROV_R_INVALID_KEY_LENGTH: c_int = 105;
/// `PROV_R_OUTPUT_BUFFER_TOO_SMALL` (106).
const PROV_R_OUTPUT_BUFFER_TOO_SMALL: c_int = 106;
/// `PROV_R_INVALID_AAD` (108).
const PROV_R_INVALID_AAD: c_int = 108;
/// `PROV_R_INVALID_IV_LENGTH` (109).
const PROV_R_INVALID_IV_LENGTH: c_int = 109;
/// `PROV_R_INVALID_TAG` (110).
const PROV_R_INVALID_TAG: c_int = 110;
/// `PROV_R_TOO_MANY_RECORDS` (126).
const PROV_R_TOO_MANY_RECORDS: c_int = 126;
/// `PROV_R_REPEATED_PARAMETER` (252).
const PROV_R_REPEATED_PARAMETER: c_int = 252;

/// `gcm_init` at `ciphercommon_gcm.c:64` (`PROV_R_INVALID_IV_LENGTH`).
const GCM_64: err_sites::ErrSite = gcm_site(64, c"gcm_init", PROV_R_INVALID_IV_LENGTH);
/// `gcm_init` at `:74` (`PROV_R_INVALID_KEY_LENGTH`).
const GCM_74: err_sites::ErrSite = gcm_site(74, c"gcm_init", PROV_R_INVALID_KEY_LENGTH);

/// `ossl_cipher_gcm_get_ctx_params_decoder` at `:201` (`PROV_R_REPEATED_PARAMETER`, `iv-generated`).
const GCM_201: err_sites::ErrSite = gcm_site(
    201,
    c"ossl_cipher_gcm_get_ctx_params_decoder",
    PROV_R_REPEATED_PARAMETER,
);
/// The same decoder at `:212` (`ivlen`).
const GCM_212: err_sites::ErrSite = gcm_site(
    212,
    c"ossl_cipher_gcm_get_ctx_params_decoder",
    PROV_R_REPEATED_PARAMETER,
);
/// The same decoder at `:221` (`iv`).
const GCM_221: err_sites::ErrSite = gcm_site(
    221,
    c"ossl_cipher_gcm_get_ctx_params_decoder",
    PROV_R_REPEATED_PARAMETER,
);
/// The same decoder at `:233` (`keylen`).
const GCM_233: err_sites::ErrSite = gcm_site(
    233,
    c"ossl_cipher_gcm_get_ctx_params_decoder",
    PROV_R_REPEATED_PARAMETER,
);
/// The same decoder at `:256` (`taglen`).
const GCM_256: err_sites::ErrSite = gcm_site(
    256,
    c"ossl_cipher_gcm_get_ctx_params_decoder",
    PROV_R_REPEATED_PARAMETER,
);
/// The same decoder at `:265` (`tag`).
const GCM_265: err_sites::ErrSite = gcm_site(
    265,
    c"ossl_cipher_gcm_get_ctx_params_decoder",
    PROV_R_REPEATED_PARAMETER,
);
/// The same decoder at `:285` (`tlsaadpad`).
const GCM_285: err_sites::ErrSite = gcm_site(
    285,
    c"ossl_cipher_gcm_get_ctx_params_decoder",
    PROV_R_REPEATED_PARAMETER,
);
/// The same decoder at `:296` (`tlsivgen`).
const GCM_296: err_sites::ErrSite = gcm_site(
    296,
    c"ossl_cipher_gcm_get_ctx_params_decoder",
    PROV_R_REPEATED_PARAMETER,
);
/// The same decoder at `:310` (`updated-iv`).
const GCM_310: err_sites::ErrSite = gcm_site(
    310,
    c"ossl_cipher_gcm_get_ctx_params_decoder",
    PROV_R_REPEATED_PARAMETER,
);

/// `ossl_cipher_gcm_set_ctx_params_decoder` at `:456` (`ivlen`).
const GCM_456: err_sites::ErrSite = gcm_site(
    456,
    c"ossl_cipher_gcm_set_ctx_params_decoder",
    PROV_R_REPEATED_PARAMETER,
);
/// The same decoder at `:471` (`tag`).
const GCM_471: err_sites::ErrSite = gcm_site(
    471,
    c"ossl_cipher_gcm_set_ctx_params_decoder",
    PROV_R_REPEATED_PARAMETER,
);
/// The same decoder at `:490` (`tlsaad`).
const GCM_490: err_sites::ErrSite = gcm_site(
    490,
    c"ossl_cipher_gcm_set_ctx_params_decoder",
    PROV_R_REPEATED_PARAMETER,
);
/// The same decoder at `:509` (`tlsivfixed`).
const GCM_509: err_sites::ErrSite = gcm_site(
    509,
    c"ossl_cipher_gcm_set_ctx_params_decoder",
    PROV_R_REPEATED_PARAMETER,
);
/// The same decoder at `:520` (`tlsivinv`).
const GCM_520: err_sites::ErrSite = gcm_site(
    520,
    c"ossl_cipher_gcm_set_ctx_params_decoder",
    PROV_R_REPEATED_PARAMETER,
);

/// `ossl_gcm_get_ctx_params` at `:339` (`PROV_R_FAILED_TO_SET_PARAMETER`, `ivlen`).
const GCM_339: err_sites::ErrSite = gcm_site(
    339,
    c"ossl_gcm_get_ctx_params",
    PROV_R_FAILED_TO_SET_PARAMETER,
);
/// The same body at `:344` (`keylen`).
const GCM_344: err_sites::ErrSite = gcm_site(
    344,
    c"ossl_gcm_get_ctx_params",
    PROV_R_FAILED_TO_SET_PARAMETER,
);
/// The same body at `:352` (`taglen`).
const GCM_352: err_sites::ErrSite = gcm_site(
    352,
    c"ossl_gcm_get_ctx_params",
    PROV_R_FAILED_TO_SET_PARAMETER,
);
/// The same body at `:361` (`PROV_R_INVALID_IV_LENGTH`, `iv`).
const GCM_361: err_sites::ErrSite =
    gcm_site(361, c"ossl_gcm_get_ctx_params", PROV_R_INVALID_IV_LENGTH);
/// The same body at `:365` (`iv`).
const GCM_365: err_sites::ErrSite = gcm_site(
    365,
    c"ossl_gcm_get_ctx_params",
    PROV_R_FAILED_TO_SET_PARAMETER,
);
/// The same body at `:374` (`PROV_R_INVALID_IV_LENGTH`, `updated-iv`).
const GCM_374: err_sites::ErrSite =
    gcm_site(374, c"ossl_gcm_get_ctx_params", PROV_R_INVALID_IV_LENGTH);
/// The same body at `:378` (`updated-iv`).
const GCM_378: err_sites::ErrSite = gcm_site(
    378,
    c"ossl_gcm_get_ctx_params",
    PROV_R_FAILED_TO_SET_PARAMETER,
);
/// The same body at `:384` (`tlsaadpad`).
const GCM_384: err_sites::ErrSite = gcm_site(
    384,
    c"ossl_gcm_get_ctx_params",
    PROV_R_FAILED_TO_SET_PARAMETER,
);
/// The same body at `:391` (`PROV_R_INVALID_TAG`, the `!enc`/unset arm).
const GCM_391: err_sites::ErrSite = gcm_site(391, c"ossl_gcm_get_ctx_params", PROV_R_INVALID_TAG);
/// The same body at `:395` (`PROV_R_INVALID_TAG`, the size arm).
const GCM_395: err_sites::ErrSite = gcm_site(395, c"ossl_gcm_get_ctx_params", PROV_R_INVALID_TAG);
/// The same body at `:400` (`tag`).
const GCM_400: err_sites::ErrSite = gcm_site(
    400,
    c"ossl_gcm_get_ctx_params",
    PROV_R_FAILED_TO_SET_PARAMETER,
);

/// `ossl_gcm_set_ctx_params` at `:557` (`PROV_R_FAILED_TO_GET_PARAMETER`, `tag` type).
const GCM_557: err_sites::ErrSite = gcm_site(
    557,
    c"ossl_gcm_set_ctx_params",
    PROV_R_FAILED_TO_GET_PARAMETER,
);
/// The same body at `:561` (`PROV_R_INVALID_TAG`).
const GCM_561: err_sites::ErrSite = gcm_site(561, c"ossl_gcm_set_ctx_params", PROV_R_INVALID_TAG);
/// The same body at `:569` (`ivlen`).
const GCM_569: err_sites::ErrSite = gcm_site(
    569,
    c"ossl_gcm_set_ctx_params",
    PROV_R_FAILED_TO_GET_PARAMETER,
);
/// The same body at `:573` (`PROV_R_INVALID_IV_LENGTH`).
const GCM_573: err_sites::ErrSite =
    gcm_site(573, c"ossl_gcm_set_ctx_params", PROV_R_INVALID_IV_LENGTH);
/// The same body at `:586` (`tlsaad` type).
const GCM_586: err_sites::ErrSite = gcm_site(
    586,
    c"ossl_gcm_set_ctx_params",
    PROV_R_FAILED_TO_GET_PARAMETER,
);
/// The same body at `:591` (`PROV_R_INVALID_AAD`).
const GCM_591: err_sites::ErrSite = gcm_site(591, c"ossl_gcm_set_ctx_params", PROV_R_INVALID_AAD);
/// The same body at `:599` (`tlsivfixed` type).
const GCM_599: err_sites::ErrSite = gcm_site(
    599,
    c"ossl_gcm_set_ctx_params",
    PROV_R_FAILED_TO_GET_PARAMETER,
);
/// The same body at `:603` (`tlsivfixed` value).
const GCM_603: err_sites::ErrSite = gcm_site(
    603,
    c"ossl_gcm_set_ctx_params",
    PROV_R_FAILED_TO_GET_PARAMETER,
);

/// `ossl_gcm_stream_update` at `:628` (`PROV_R_OUTPUT_BUFFER_TOO_SMALL`).
const GCM_628: err_sites::ErrSite = gcm_site(
    628,
    c"ossl_gcm_stream_update",
    PROV_R_OUTPUT_BUFFER_TOO_SMALL,
);
/// The same body at `:633` (`PROV_R_CIPHER_OPERATION_FAILED`).
const GCM_633: err_sites::ErrSite = gcm_site(
    633,
    c"ossl_gcm_stream_update",
    PROV_R_CIPHER_OPERATION_FAILED,
);
/// `ossl_gcm_cipher` at `:666` (`PROV_R_OUTPUT_BUFFER_TOO_SMALL`).
const GCM_666: err_sites::ErrSite =
    gcm_site(666, c"ossl_gcm_cipher", PROV_R_OUTPUT_BUFFER_TOO_SMALL);
/// `gcm_tls_cipher` at `:844` (`PROV_R_TOO_MANY_RECORDS`).
const GCM_844: err_sites::ErrSite = gcm_site(844, c"gcm_tls_cipher", PROV_R_TOO_MANY_RECORDS);

/// The nine keys `ossl_cipher_gcm_get_ctx_params_decoder` locates, each with the line of its own
/// repeated-parameter raise (`ciphercommon_gcm.c:201-310`). Order is the decoder's switch order.
const GCM_GET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 9] = [
    (&GCM_201, OSSL_CIPHER_PARAM_AEAD_IV_GENERATED),
    (&GCM_212, OSSL_CIPHER_PARAM_IVLEN),
    (&GCM_221, OSSL_CIPHER_PARAM_IV),
    (&GCM_233, OSSL_CIPHER_PARAM_KEYLEN),
    (&GCM_256, OSSL_CIPHER_PARAM_AEAD_TAGLEN),
    (&GCM_265, OSSL_CIPHER_PARAM_AEAD_TAG),
    (&GCM_285, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD),
    (&GCM_296, OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN),
    (&GCM_310, OSSL_CIPHER_PARAM_UPDATED_IV),
];

/// The five keys `ossl_cipher_gcm_set_ctx_params_decoder` locates (`ciphercommon_gcm.c:456-520`).
const GCM_SET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 5] = [
    (&GCM_456, OSSL_CIPHER_PARAM_IVLEN),
    (&GCM_471, OSSL_CIPHER_PARAM_AEAD_TAG),
    (&GCM_490, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD),
    (&GCM_509, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED),
    (&GCM_520, OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV),
];

/// `int ossl_prov_is_running(void)` — `providers/prov_running.c`, as this crate's cipher and MAC
/// halves already spell it: the default provider is always in a happy state on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// The authority's `ERR_raise(...); return 0;` pair.
#[inline]
fn fail_at(site: &err_sites::ErrSite) -> c_int {
    // SAFETY: `site` is a compile-time constant whose string pointers are `'static`.
    unsafe { raise_site(site) };
    0
}

/// A refusal the authority makes without raising: the propagation arms and the `NULL`
/// `ossl_prov_is_running` arms.
#[inline]
fn fail() -> c_int {
    0
}

// ---------------------------------------------------------------------------------------------
// `PROV_GCM_CTX` and `PROV_GCM_HW`
// ---------------------------------------------------------------------------------------------

/// The authority's five `unsigned int : 1` fields at `prov/ciphercommon_gcm.h:69-73`
/// (`enc`, `pad`, `key_set`, `iv_gen_rand`, `iv_gen`).
///
/// **One byte, measured.** The five bits of one `unsigned int` occupy a single byte here because
/// the member that follows, `unsigned char iv[GCM_IV_MAX_SIZE]`, is byte-aligned and the ABI's
/// storage unit is truncated to the bits actually used: the pinned build reports
/// `offsetof(PROV_GCM_CTX, iv) == 85`, i.e. `iv_state` at 80..84 and the bits at 84..85. Modelling
/// the bits as a `c_uint` — as the CCM landing did, where a `size_t` followed — would move `iv` to
/// 88 and `buf` to 216; the total would still be 704 only because the slack before `libctx`
/// absorbs it, so the byte model is what reproduces the authority's member offsets.
#[repr(C)]
pub(crate) struct GcmFlags {
    /// The packed flag bits.
    bits: c_uchar,
}

impl GcmFlags {
    /// `enc == 1`.
    const ENC: c_uchar = 1 << 0;
    /// `pad == 1`.
    const PAD: c_uchar = 1 << 1;
    /// `key_set == 1`.
    const KEY_SET: c_uchar = 1 << 2;
    /// `iv_gen_rand == 1`.
    const IV_GEN_RAND: c_uchar = 1 << 3;
    /// `iv_gen == 1`.
    const IV_GEN: c_uchar = 1 << 4;

    /// `ctx->enc` as a `c_uint`, so the authority's `== 0`/`!= 0` tests read unchanged.
    fn enc(&self) -> c_uint {
        c_uint::from(self.bits & Self::ENC != 0)
    }
    /// `ctx->enc = ...`.
    fn set_enc(&mut self, value: c_int) {
        self.set_bit(Self::ENC, value != 0);
    }
    /// `ctx->pad = ...`.
    fn set_pad(&mut self, value: bool) {
        self.set_bit(Self::PAD, value);
    }
    /// `ctx->key_set` as a `c_uint`.
    fn key_set(&self) -> c_uint {
        c_uint::from(self.bits & Self::KEY_SET != 0)
    }
    /// `ctx->key_set = ...`.
    fn set_key_set(&mut self, value: bool) {
        self.set_bit(Self::KEY_SET, value);
    }
    /// `ctx->iv_gen_rand` as a `c_uint`.
    fn iv_gen_rand(&self) -> c_uint {
        c_uint::from(self.bits & Self::IV_GEN_RAND != 0)
    }
    /// `ctx->iv_gen_rand = 1`.
    fn set_iv_gen_rand(&mut self) {
        self.set_bit(Self::IV_GEN_RAND, true);
    }
    /// `ctx->iv_gen` as a `c_uint`.
    fn iv_gen(&self) -> c_uint {
        c_uint::from(self.bits & Self::IV_GEN != 0)
    }
    /// `ctx->iv_gen = 1`.
    fn set_iv_gen(&mut self) {
        self.set_bit(Self::IV_GEN, true);
    }
    /// The one-bit assignment.
    fn set_bit(&mut self, mask: c_uchar, value: bool) {
        if value {
            self.bits |= mask;
        } else {
            self.bits &= !mask;
        }
    }
}

/// The six hardware methods of `struct prov_gcm_hw_st` — `prov/ciphercommon_gcm.h:90-97`. Every
/// member is a `PROV_CIPHER_FUNC` over the *provider* context, not the cipher context.
pub(crate) struct ProvGcmHw {
    /// `OSSL_GCM_setkey_fn setkey`.
    pub setkey: GcmSetkeyFn,
    /// `OSSL_GCM_setiv_fn setiv`.
    pub setiv: GcmSetivFn,
    /// `OSSL_GCM_aadupdate_fn aadupdate`.
    pub aadupdate: GcmAadupdateFn,
    /// `OSSL_GCM_cipherupdate_fn cipherupdate`.
    pub cipherupdate: GcmCipherupdateFn,
    /// `OSSL_GCM_cipherfinal_fn cipherfinal`.
    pub cipherfinal: GcmCipherfinalFn,
    /// `OSSL_GCM_oneshot_fn oneshot`.
    pub oneshot: GcmOneshotFn,
}

/// `PROV_CIPHER_FUNC(int, GCM_setkey, ...)` — `prov/ciphercommon_gcm.h:84`.
type GcmSetkeyFn = unsafe fn(*mut ProvGcmCtx, *const c_uchar, usize) -> c_int;
/// `PROV_CIPHER_FUNC(int, GCM_setiv, ...)` — `prov/ciphercommon_gcm.h:85`.
type GcmSetivFn = unsafe fn(*mut ProvGcmCtx, *const c_uchar, usize) -> c_int;
/// `PROV_CIPHER_FUNC(int, GCM_aadupdate, ...)` — `prov/ciphercommon_gcm.h:86`.
type GcmAadupdateFn = unsafe fn(*mut ProvGcmCtx, *const c_uchar, usize) -> c_int;
/// `PROV_CIPHER_FUNC(int, GCM_cipherupdate, ...)` — `prov/ciphercommon_gcm.h:87`.
type GcmCipherupdateFn = unsafe fn(*mut ProvGcmCtx, *const c_uchar, usize, *mut c_uchar) -> c_int;
/// `PROV_CIPHER_FUNC(int, GCM_cipherfinal, ...)` — `prov/ciphercommon_gcm.h:88`.
type GcmCipherfinalFn = unsafe fn(*mut ProvGcmCtx, *mut c_uchar) -> c_int;
/// `PROV_CIPHER_FUNC(int, GCM_oneshot, ...)` — `prov/ciphercommon_gcm.h:89`.
#[allow(clippy::type_complexity)]
type GcmOneshotFn = unsafe fn(
    *mut ProvGcmCtx,
    *mut c_uchar,
    usize,
    *const c_uchar,
    usize,
    *mut c_uchar,
    *mut c_uchar,
    usize,
) -> c_int;

/// `PROV_GCM_CTX` — `prov/ciphercommon_gcm.h:51-82`.
///
/// The member order is the authority's, and the sizes are the measured ones (this module's doc
/// table). The embedded GCM state is the crate's compact `GcmCtx`, which has the same
/// eight-byte alignment as the authority's `GCM128_CONTEXT` and so lands at the authority's own
/// `gcm` offset of 248 (see `GcmCtx`'s accessors for the measurement); the named reserve carries
/// the rest of the authority's 448-byte `GCM128_CONTEXT` region so that `ctr` lands at 696 and
/// the object totals 704.
#[repr(C)]
pub(crate) struct ProvGcmCtx {
    /// `unsigned int mode` — written by `ossl_gcm_initctx`, read by nothing in this engine.
    #[allow(dead_code)] // size-only member: the authority writes it and never reads it
    pub mode: c_uint,
    /// `size_t keylen`.
    pub keylen: usize,
    /// `size_t ivlen`.
    pub ivlen: usize,
    /// `size_t taglen` — `UNINITIALISED_SIZET` until a tag is set or produced.
    pub taglen: usize,
    /// `size_t tls_aad_pad_sz`.
    pub tls_aad_pad_sz: usize,
    /// `size_t tls_aad_len` — `UNINITIALISED_SIZET` until a TLS AAD arrives.
    pub tls_aad_len: usize,
    /// `uint64_t tls_enc_records`.
    pub tls_enc_records: u64,
    /// `size_t num` — unused by GCM; a byte of the allocation request.
    #[allow(dead_code)] // size-only member: present only as bytes of the allocation request
    pub num: usize,
    /// `size_t bufsz` — unused by GCM; a byte of the allocation request.
    #[allow(dead_code)] // size-only member: present only as bytes of the allocation request
    pub bufsz: usize,
    /// `uint64_t flags` — unused by GCM; a byte of the allocation request.
    #[allow(dead_code)] // size-only member: present only as bytes of the allocation request
    pub flags: u64,
    /// `unsigned int iv_state` — one of the `IV_STATE_*` values.
    pub iv_state: c_uint,
    /// The five `unsigned int : 1` fields, packed into one byte (`GcmFlags`).
    pub bits: GcmFlags,
    /// `unsigned char iv[GCM_IV_MAX_SIZE]`.
    pub iv: [c_uchar; GCM_IV_MAX_SIZE],
    /// `unsigned char buf[AES_BLOCK_SIZE]` — the tag buffer, and the saved TLS AAD.
    pub buf: [c_uchar; GCM_BLOCK_SIZE],
    /// `OSSL_LIB_CTX *libctx` — `PROV_LIBCTX_OF(provctx)`, the acquisition `RAND_bytes_ex` uses.
    pub libctx: *mut c_void,
    /// `const PROV_GCM_HW *hw`.
    pub hw: *const ProvGcmHw,
    /// `GCM128_CONTEXT gcm` — the crate's compact model.
    pub gcm: GcmCtx,
    /// The tail of the authority's 448-byte `GCM128_CONTEXT` that `GcmCtx` does not occupy; see
    /// the struct's note. `[448 - 152]`.
    #[allow(dead_code)] // size-only member: see the struct's note
    pub gcm_reserve: [c_uchar; 296],
    /// `ctr128_f ctr` — installed by the per-algorithm `initkey`; NULL on this profile.
    pub ctr: Option<Ctr128F>,
}

/// A `#[repr(C)]` view of [`GcmCtx`] that exposes its trailing `key`.
///
/// `cipher_aes_gcm.c:49-50` (and its ARIA and SM4 siblings) repair a shallow copy's
/// `dctx->base.gcm.key` to point at the copy's own schedule; the crate's `GcmCtx` keeps `key`
/// private, with `CRYPTO_gcm128_init` as its only writer, and this module may not add a method to
/// it. The repair is therefore written through this mirror, whose field types and order are
/// `GcmCtx`'s exactly and whose size and `key` offset the unit test pins against `GcmCtx` itself.
/// Only `key` is ever read or written through it; the other members exist to place it.
#[repr(C)]
#[allow(dead_code)] // only `key` is used; the rest place it
struct GcmCtxMirror {
    h: [u64; 2],
    xi: [u64; 2],
    eki: [c_uchar; 16],
    ek0: [c_uchar; 16],
    yi: [c_uchar; 16],
    buf: [c_uchar; 16],
    aad_buf: [c_uchar; 16],
    aad_len: u64,
    msg_len: u64,
    mres: c_uint,
    ares: c_uint,
    block: Option<Block128F>,
    key: *mut c_void,
}

/// `dctx->base.gcm.key = &dctx->ks.ks` — the one write the provider GCM contexts make outside the
/// mode module. `gcm` is the copy's own embedded context; `key` is the copy's own schedule.
///
/// # Safety
/// `gcm` points at a live `GcmCtx` (the `gcm` member of a `ProvGcmCtx`), and `key` designates the
/// schedule the context's block function reads.
unsafe fn gcm_repoint_key(gcm: *mut GcmCtx, key: *mut c_void) {
    // SAFETY: `GcmCtxMirror` is layout-identical to `GcmCtx` (the unit test asserts size and the
    // `key` offset), so this writes `GcmCtx::key` and nothing else.
    unsafe {
        (*gcm.cast::<GcmCtxMirror>()).key = key;
    }
}

// ---------------------------------------------------------------------------------------------
// `ciphercommon_gcm.c` — the shared engine
// ---------------------------------------------------------------------------------------------

/// `void ossl_gcm_initctx(void *provctx, PROV_GCM_CTX *ctx, size_t keybits, const PROV_GCM_HW *hw)`
/// — `ciphercommon_gcm.c.in:37-48`. `ctx` is zeroed by the caller's `OPENSSL_zalloc`.
///
/// # Safety
/// `ctx` is a live, zeroed `ProvGcmCtx`; `provctx` is the creating provider's context or NULL
/// (`PROV_LIBCTX_OF` is itself NULL-safe).
unsafe fn ossl_gcm_initctx(
    provctx: *mut c_void,
    ctx: *mut ProvGcmCtx,
    keybits: usize,
    hw: *const ProvGcmHw,
) {
    // SAFETY: the caller's contract.
    unsafe {
        (*ctx).bits.set_pad(true);
        (*ctx).mode = EVP_CIPH_GCM_MODE;
        (*ctx).taglen = UNINITIALISED_SIZET;
        (*ctx).tls_aad_len = UNINITIALISED_SIZET;
        (*ctx).ivlen = EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN;
        (*ctx).keylen = keybits / 8;
        (*ctx).hw = hw;
        (*ctx).libctx = prov_libctx_of(provctx);
    }
}

/// `gcm_init` — `ciphercommon_gcm.c.in:53-84`.
///
/// # Safety
/// The dispatch contract.
unsafe fn gcm_init(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
    enc: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvGcmCtx>();

        if is_running() == 0 {
            return 0;
        }

        (*ctx).bits.set_enc(enc);

        if !iv.is_null() {
            if ivlen == 0 || ivlen > GCM_IV_MAX_SIZE {
                return fail_at(&GCM_64);
            }
            (*ctx).ivlen = ivlen;
            ptr::copy_nonoverlapping(iv, (*ctx).iv.as_mut_ptr(), ivlen);
            (*ctx).iv_state = IV_STATE_BUFFERED;
        }

        if !key.is_null() {
            if keylen != (*ctx).keylen {
                return fail_at(&GCM_74);
            }
            let hw = (*ctx).hw;
            if ((*hw).setkey)(ctx, key, (*ctx).keylen) == 0 {
                return 0;
            }
            (*ctx).tls_enc_records = 0;
        }
        ossl_gcm_set_ctx_params(vctx, params)
    }
}

/// `ossl_gcm_einit` — `ciphercommon_gcm.c.in:86-91`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_gcm_einit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { gcm_init(vctx, key, keylen, iv, ivlen, params, 1) }
}

/// `ossl_gcm_dinit` — `ciphercommon_gcm.c.in:93-98`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_gcm_dinit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { gcm_init(vctx, key, keylen, iv, ivlen, params, 0) }
}

/// `static void ctr64_inc(unsigned char *counter)` — `ciphercommon_gcm.c.in:101-114`: increment
/// the low sixty-four bits of the sixteen-byte `counter`, big-endian, stopping at the first byte
/// that does not wrap.
///
/// # Safety
/// `counter` points to at least eight live bytes.
unsafe fn ctr64_inc(counter: *mut c_uchar) {
    // SAFETY: the caller's contract; `n` stays within `[0, 8)`.
    unsafe {
        let mut n: isize = 8;
        loop {
            n -= 1;
            let c = counter.offset(n).read().wrapping_add(1);
            counter.offset(n).write(c);
            if c > 0 {
                return;
            }
            if n <= 0 {
                return;
            }
        }
    }
}

/// `static int getivgen(PROV_GCM_CTX *ctx, unsigned char *out, size_t olen)` —
/// `ciphercommon_gcm.c.in:116-132`. The `OLEN`/`INVIV` TLS-IV generation the get-ctx-params
/// `ivgen` arm reaches.
///
/// # Safety
/// `ctx` is live; `out` is writable for `olen` bytes (or for `ctx->ivlen` when `olen` is 0 or
/// larger).
unsafe fn getivgen(ctx: *mut ProvGcmCtx, out: *mut c_uchar, mut olen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if (*ctx).bits.iv_gen() == 0 || (*ctx).bits.key_set() == 0 {
            return 0;
        }
        let hw = (*ctx).hw;
        if ((*hw).setiv)(ctx, (*ctx).iv.as_ptr(), (*ctx).ivlen) == 0 {
            return 0;
        }
        if olen == 0 || olen > (*ctx).ivlen {
            olen = (*ctx).ivlen;
        }
        ptr::copy_nonoverlapping(
            (*ctx).iv.as_ptr().add((*ctx).ivlen.wrapping_sub(olen)),
            out,
            olen,
        );
        // The invocation field is at least eight bytes, so only the last eight are incremented.
        ctr64_inc((*ctx).iv.as_mut_ptr().add((*ctx).ivlen.wrapping_sub(8)));
        (*ctx).iv_state = IV_STATE_COPIED;
        1
    }
}

/// `static int setivinv(PROV_GCM_CTX *ctx, unsigned char *in, size_t inl)` —
/// `ciphercommon_gcm.c.in:134-146`.
///
/// # Safety
/// `ctx` is live; `in` is readable for `inl` bytes and `inl <= ctx->ivlen`.
unsafe fn setivinv(ctx: *mut ProvGcmCtx, in_: *mut c_uchar, inl: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if (*ctx).bits.iv_gen() == 0 || (*ctx).bits.key_set() == 0 || (*ctx).bits.enc() != 0 {
            return 0;
        }
        ptr::copy_nonoverlapping(
            in_,
            (*ctx).iv.as_mut_ptr().add((*ctx).ivlen.wrapping_sub(inl)),
            inl,
        );
        let hw = (*ctx).hw;
        if ((*hw).setiv)(ctx, (*ctx).iv.as_ptr(), (*ctx).ivlen) == 0 {
            return 0;
        }
        (*ctx).iv_state = IV_STATE_COPIED;
        1
    }
}

/// `const OSSL_PARAM *ossl_gcm_gettable_ctx_params(...)` — `ciphercommon_gcm.c.in:162-166`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_gcm_gettable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    GCM_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `int ossl_gcm_get_ctx_params(void *vctx, OSSL_PARAM params[])` —
/// `ciphercommon_gcm.c.in:168-254`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_gcm_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &GCM_GET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }
        let ctx = vctx.cast::<ProvGcmCtx>();

        let p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if !p.is_null() && OSSL_PARAM_set_size_t(p, (*ctx).ivlen) == 0 {
            return fail_at(&GCM_339);
        }

        let p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if !p.is_null() && OSSL_PARAM_set_size_t(p, (*ctx).keylen) == 0 {
            return fail_at(&GCM_344);
        }

        let p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
        if !p.is_null() {
            let taglen = if (*ctx).taglen != UNINITIALISED_SIZET {
                (*ctx).taglen
            } else {
                GCM_TAG_MAX_SIZE
            };
            if OSSL_PARAM_set_size_t(p, taglen) == 0 {
                return fail_at(&GCM_352);
            }
        }

        let p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if !p.is_null() {
            if (*ctx).iv_state == IV_STATE_UNINITIALISED {
                return 0;
            }
            if !(*p).data.is_null() && (*ctx).ivlen > (*p).data_size {
                return fail_at(&GCM_361);
            }
            if OSSL_PARAM_set_octet_string_or_ptr(p, (*ctx).iv.as_ptr().cast(), (*ctx).ivlen) == 0 {
                return fail_at(&GCM_365);
            }
        }

        let p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
        if !p.is_null() {
            if (*ctx).iv_state == IV_STATE_UNINITIALISED {
                return 0;
            }
            if !(*p).data.is_null() && (*ctx).ivlen > (*p).data_size {
                return fail_at(&GCM_374);
            }
            if OSSL_PARAM_set_octet_string_or_ptr(p, (*ctx).iv.as_ptr().cast(), (*ctx).ivlen) == 0 {
                return fail_at(&GCM_378);
            }
        }

        let p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
        if !p.is_null() && OSSL_PARAM_set_size_t(p, (*ctx).tls_aad_pad_sz) == 0 {
            return fail_at(&GCM_384);
        }

        let p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if !p.is_null() {
            let sz = (*p).data_size;
            if (*ctx).bits.enc() == 0 || (*ctx).taglen == UNINITIALISED_SIZET {
                return fail_at(&GCM_391);
            }
            if !(*p).data.is_null() && (sz > EVP_GCM_TLS_TAG_LEN || sz == 0) {
                return fail_at(&GCM_395);
            }
            if OSSL_PARAM_set_octet_string(p, (*ctx).buf.as_ptr().cast(), sz) == 0 {
                return fail_at(&GCM_400);
            }
        }

        let p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN);
        if !p.is_null()
            && ((*p).data.is_null()
                || (*p).data_type != OSSL_PARAM_OCTET_STRING
                || getivgen(ctx, (*p).data.cast::<c_uchar>(), (*p).data_size) == 0)
        {
            return 0;
        }

        let p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_IV_GENERATED);
        if !p.is_null() && OSSL_PARAM_set_uint(p, (*ctx).bits.iv_gen_rand()) == 0 {
            return 0;
        }

        1
    }
}

/// `const OSSL_PARAM *ossl_gcm_settable_ctx_params(...)` — `ciphercommon_gcm.c.in:267-271`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_gcm_settable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    GCM_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `int ossl_gcm_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `ciphercommon_gcm.c.in:273-344`.
///
/// The tag arm is the ordering the CCM landing's comment describes one construction over: on the
/// encryption side a *tag value* is refused (`PROV_R_INVALID_TAG`) because the tag is an output,
/// while on decryption it is how the expected tag reaches `ctx->buf`. The IV-length arm resets
/// `iv_state` to `IV_STATE_FINISHED` when the length moves after an IV was set, invalidating it.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_gcm_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &GCM_SET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }
        let ctx = vctx.cast::<ProvGcmCtx>();

        let p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if !p.is_null() {
            let mut sz = 0usize;
            let mut vp = (*ctx).buf.as_mut_ptr().cast::<c_void>();
            if OSSL_PARAM_get_octet_string(p, &mut vp, EVP_GCM_TLS_TAG_LEN, &mut sz) == 0 {
                return fail_at(&GCM_557);
            }
            if sz == 0 || (*ctx).bits.enc() != 0 {
                return fail_at(&GCM_561);
            }
            (*ctx).taglen = sz;
        }

        let p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
        if !p.is_null() {
            let mut sz = 0usize;
            if OSSL_PARAM_get_size_t(p, &mut sz) == 0 {
                return fail_at(&GCM_569);
            }
            if sz == 0 || sz > GCM_IV_MAX_SIZE {
                return fail_at(&GCM_573);
            }
            if (*ctx).ivlen != sz {
                /* If the iv was already set or autogenerated, it is invalid. */
                if (*ctx).iv_state != IV_STATE_UNINITIALISED {
                    (*ctx).iv_state = IV_STATE_FINISHED;
                }
                (*ctx).ivlen = sz;
            }
        }

        let p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                return fail_at(&GCM_586);
            }
            let sz = gcm_tls_init(ctx, (*p).data.cast::<c_uchar>(), (*p).data_size);
            if sz == 0 {
                return fail_at(&GCM_591);
            }
            (*ctx).tls_aad_pad_sz = sz as usize;
        }

        let p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                return fail_at(&GCM_599);
            }
            if gcm_tls_iv_set_fixed(ctx, (*p).data.cast::<c_uchar>(), (*p).data_size) == 0 {
                return fail_at(&GCM_603);
            }
        }

        let p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV);
        if !p.is_null()
            && ((*p).data.is_null()
                || (*p).data_type != OSSL_PARAM_OCTET_STRING
                || setivinv(ctx, (*p).data.cast::<c_uchar>(), (*p).data_size) == 0)
        {
            return fail();
        }

        1
    }
}

/// `int ossl_gcm_stream_update(...)` — `ciphercommon_gcm.c.in:346-366`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_gcm_stream_update(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if inl == 0 {
            *outl = 0;
            return 1;
        }

        if outsize < inl {
            return fail_at(&GCM_628);
        }

        if gcm_cipher_internal(vctx.cast(), out, outl, in_, inl) <= 0 {
            return fail_at(&GCM_633);
        }
        1
    }
}

/// `int ossl_gcm_stream_final(...)` — `ciphercommon_gcm.c.in:368-383`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_gcm_stream_final(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return 0;
        }
        if gcm_cipher_internal(vctx.cast(), out, outl, ptr::null(), 0) <= 0 {
            return 0;
        }
        *outl = 0;
        1
    }
}

/// `int ossl_gcm_cipher(...)` — `ciphercommon_gcm.c.in:385-404`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_gcm_cipher(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return 0;
        }

        if outsize < inl {
            return fail_at(&GCM_666);
        }

        if gcm_cipher_internal(vctx.cast(), out, outl, in_, inl) <= 0 {
            return 0;
        }
        *outl = inl;
        1
    }
}

/// `static int gcm_iv_generate(PROV_GCM_CTX *ctx, int offset)` —
/// `ciphercommon_gcm.c.in:414-428`. The no-IV encrypting arm and the encrypting TLS-fixed-IV arm
/// both reach it; it is why these rows were a Phase 9 hand-off (D234).
///
/// # Safety
/// `ctx` is live and `ctx->iv` is writable for `ctx->ivlen`.
unsafe fn gcm_iv_generate(ctx: *mut ProvGcmCtx, offset: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let sz = (*ctx).ivlen.wrapping_sub(offset);

        /* Must be at least 96 bits. */
        if sz == 0 || (*ctx).ivlen < GCM_IV_DEFAULT_SIZE {
            return 0;
        }

        /* Use DRBG to generate random iv. */
        if RAND_bytes_ex((*ctx).libctx, (*ctx).iv.as_mut_ptr().add(offset), sz, 0) <= 0 {
            return 0;
        }
        (*ctx).iv_state = IV_STATE_BUFFERED;
        (*ctx).bits.set_iv_gen_rand();
        1
    }
}

/// `static int gcm_cipher_internal(...)` — `ciphercommon_gcm.c.in:430-486`.
///
/// # Safety
/// `ctx` is live; `out`/`in_` follow the dispatch contract.
unsafe fn gcm_cipher_internal(
    ctx: *mut ProvGcmCtx,
    out: *mut c_uchar,
    padlen: *mut usize,
    in_: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut olen = 0usize;
        let mut rv = 0;

        if (*ctx).tls_aad_len != UNINITIALISED_SIZET {
            return gcm_tls_cipher(ctx, out, padlen, in_, len);
        }

        'arm: {
            if (*ctx).bits.key_set() == 0 || (*ctx).iv_state == IV_STATE_FINISHED {
                break 'arm;
            }

            // FIPS requires generation of AES-GCM IVs inside the module; an IV may still be set
            // externally, and an encrypting context with none generates one here.
            if (*ctx).iv_state == IV_STATE_UNINITIALISED
                && ((*ctx).bits.enc() == 0 || gcm_iv_generate(ctx, 0) == 0)
            {
                break 'arm;
            }

            if (*ctx).iv_state == IV_STATE_BUFFERED {
                let hw = (*ctx).hw;
                if ((*hw).setiv)(ctx, (*ctx).iv.as_ptr(), (*ctx).ivlen) == 0 {
                    break 'arm;
                }
                (*ctx).iv_state = IV_STATE_COPIED;
            }

            if !in_.is_null() {
                let hw = (*ctx).hw;
                // The input is AAD if out is NULL.
                if out.is_null() {
                    if ((*hw).aadupdate)(ctx, in_, len) == 0 {
                        break 'arm;
                    }
                } else if ((*hw).cipherupdate)(ctx, in_, len, out) == 0 {
                    break 'arm;
                }
            } else {
                // The tag must be set before actually decrypting data.
                if (*ctx).bits.enc() == 0 && (*ctx).taglen == UNINITIALISED_SIZET {
                    break 'arm;
                }
                let hw = (*ctx).hw;
                if ((*hw).cipherfinal)(ctx, (*ctx).buf.as_mut_ptr()) == 0 {
                    break 'arm;
                }
                (*ctx).iv_state = IV_STATE_FINISHED; /* Don't reuse the IV */
                rv = 1;
                break 'arm;
            }
            olen = len;
            rv = 1;
            break 'arm;
        }

        *padlen = olen;
        rv
    }
}

/// `static int gcm_tls_init(PROV_GCM_CTX *dat, unsigned char *aad, size_t aad_len)` —
/// `ciphercommon_gcm.c.in:488-517`.
///
/// # Safety
/// `ctx` is live; `aad` is readable for `alen` bytes; `alen == EVP_AEAD_TLS1_AAD_LEN` is required.
unsafe fn gcm_tls_init(ctx: *mut ProvGcmCtx, aad: *const c_uchar, alen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 || alen != EVP_AEAD_TLS1_AAD_LEN {
            return 0;
        }

        /* Save the aad for later use. */
        ptr::copy_nonoverlapping(aad, (*ctx).buf.as_mut_ptr(), alen);
        (*ctx).tls_aad_len = alen;

        let mut len = ((*ctx).buf[alen - 2] as usize) << 8 | (*ctx).buf[alen - 1] as usize;
        /* Correct length for explicit iv. */
        if len < EVP_GCM_TLS_EXPLICIT_IV_LEN {
            return 0;
        }
        len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;

        /* If decrypting correct for tag too. */
        if (*ctx).bits.enc() == 0 {
            if len < EVP_GCM_TLS_TAG_LEN {
                return 0;
            }
            len -= EVP_GCM_TLS_TAG_LEN;
        }
        (*ctx).buf[alen - 2] = (len >> 8) as c_uchar;
        (*ctx).buf[alen - 1] = (len & 0xff) as c_uchar;
        /* Extra padding: tag appended to record. */
        EVP_GCM_TLS_TAG_LEN as c_int
    }
}

/// `static int gcm_tls_iv_set_fixed(PROV_GCM_CTX *ctx, unsigned char *iv, size_t len)` —
/// `ciphercommon_gcm.c.in:519-543`.
///
/// # Safety
/// `ctx` is live; `iv` is readable for `len` bytes (and `len <= ctx->ivlen` on every path that does
/// not take the whole-IV restore arm). The encrypting arm draws the invocation field from the DRBG.
unsafe fn gcm_tls_iv_set_fixed(ctx: *mut ProvGcmCtx, iv: *const c_uchar, len: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        /* Special case: -1 length restores whole IV. */
        if len == UNINITIALISED_SIZET {
            ptr::copy_nonoverlapping(iv, (*ctx).iv.as_mut_ptr(), (*ctx).ivlen);
            (*ctx).bits.set_iv_gen();
            (*ctx).iv_state = IV_STATE_BUFFERED;
            return 1;
        }
        /* Fixed field must be at least 4 bytes and invocation field at least 8. The width
         * arithmetic is the authority's `size_t` subtraction, so `wrapping_sub` states its
         * semantics rather than panicking under this profile's `overflow-checks`. */
        if len < EVP_GCM_TLS_FIXED_IV_LEN
            || (*ctx).ivlen.wrapping_sub(len) < EVP_GCM_TLS_EXPLICIT_IV_LEN
        {
            return 0;
        }
        if len > 0 {
            ptr::copy_nonoverlapping(iv, (*ctx).iv.as_mut_ptr(), len);
        }
        if (*ctx).bits.enc() != 0 {
            if RAND_bytes_ex(
                (*ctx).libctx,
                (*ctx).iv.as_mut_ptr().add(len),
                (*ctx).ivlen.wrapping_sub(len),
                0,
            ) <= 0
            {
                return 0;
            }
            (*ctx).bits.set_iv_gen_rand();
        }
        (*ctx).bits.set_iv_gen();
        (*ctx).iv_state = IV_STATE_BUFFERED;
        1
    }
}

/// `static int gcm_tls_cipher(...)` — `ciphercommon_gcm.c.in:551-612`.
///
/// # Safety
/// `ctx` is live; `out`/`in_` follow the dispatch contract, and encrypt/decrypt must be in place.
unsafe fn gcm_tls_cipher(
    ctx: *mut ProvGcmCtx,
    out: *mut c_uchar,
    padlen: *mut usize,
    in_: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut rv = 0;
        let arg = EVP_GCM_TLS_EXPLICIT_IV_LEN;
        let mut plen = 0usize;
        let mut in_ = in_;

        'arm: {
            if is_running() == 0 || (*ctx).bits.key_set() == 0 {
                break 'arm;
            }

            /* Encrypt/decrypt must be performed in place. */
            if in_.is_null()
                || out != in_.cast_mut()
                || len < EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN
            {
                break 'arm;
            }

            /* FIPS 140-2 IG A.5: fail after 2^64 - 1 keys, on the encrypting side only. */
            if (*ctx).bits.enc() != 0 {
                (*ctx).tls_enc_records = (*ctx).tls_enc_records.wrapping_add(1);
                if (*ctx).tls_enc_records == 0 {
                    // Inside this function's one `unsafe` block; the `err:` tail below still runs.
                    raise_site(&GCM_844);
                    break 'arm;
                }
            }

            /* Set IV from start of buffer or generate IV and write to start of buffer. */
            if (*ctx).bits.enc() != 0 {
                if getivgen(ctx, out, arg) == 0 {
                    break 'arm;
                }
            } else if setivinv(ctx, out, arg) == 0 {
                break 'arm;
            }

            /* Fix buffer and length to point to payload. */
            in_ = in_.add(EVP_GCM_TLS_EXPLICIT_IV_LEN);
            let out = out.add(EVP_GCM_TLS_EXPLICIT_IV_LEN);
            let len = len - (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN);

            let tag: *mut c_uchar = if (*ctx).bits.enc() != 0 {
                out.add(len)
            } else {
                in_.add(len).cast_mut()
            };
            let hw = (*ctx).hw;
            if ((*hw).oneshot)(
                ctx,
                (*ctx).buf.as_mut_ptr(),
                (*ctx).tls_aad_len,
                in_,
                len,
                out,
                tag,
                EVP_GCM_TLS_TAG_LEN,
            ) == 0
            {
                if (*ctx).bits.enc() == 0 {
                    OPENSSL_cleanse(out.cast(), len);
                }
                break 'arm;
            }
            if (*ctx).bits.enc() != 0 {
                plen = len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
            } else {
                plen = len;
            }
            rv = 1;
            break 'arm;
        }

        (*ctx).iv_state = IV_STATE_FINISHED;
        (*ctx).tls_aad_len = UNINITIALISED_SIZET;
        *padlen = plen;
        rv
    }
}

/// `static const OSSL_PARAM ossl_cipher_gcm_set_ctx_params_list[]` — the generated list at
/// `ciphercommon_gcm.c:420-427` (`ciphercommon_gcm.c.in:257-264`).
static GCM_SETTABLE_CTX_PARAMS: [OsslParam; 6] = [
    param_size_t(OSSL_CIPHER_PARAM_IVLEN),
    param_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG),
    param_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD),
    param_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED),
    param_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV),
    END,
];

/// `static const OSSL_PARAM ossl_cipher_gcm_get_ctx_params_list[]` — the generated list at
/// `ciphercommon_gcm.c:149-161` (`ciphercommon_gcm.c.in:149-159`).
static GCM_GETTABLE_CTX_PARAMS: [OsslParam; 10] = [
    param_size_t(OSSL_CIPHER_PARAM_KEYLEN),
    param_size_t(OSSL_CIPHER_PARAM_IVLEN),
    param_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN),
    param_octet_string(OSSL_CIPHER_PARAM_IV),
    param_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV),
    param_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG),
    param_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD),
    param_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN),
    param_uint(OSSL_CIPHER_PARAM_AEAD_IV_GENERATED),
    END,
];

// ---------------------------------------------------------------------------------------------
// `ciphercommon_gcm_hw.c` — the five portable hardware methods
// ---------------------------------------------------------------------------------------------

/// `int ossl_gcm_setiv(PROV_GCM_CTX *ctx, const unsigned char *iv, size_t ivlen)` —
/// `ciphercommon_gcm_hw.c:13-17`.
///
/// # Safety
/// The `PROV_GCM_HW::setiv` contract.
unsafe fn ossl_gcm_setiv(ctx: *mut ProvGcmCtx, iv: *const c_uchar, ivlen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_gcm128_setiv(ptr::addr_of_mut!((*ctx).gcm), iv, ivlen);
        1
    }
}

/// `int ossl_gcm_aad_update(PROV_GCM_CTX *ctx, const unsigned char *aad, size_t aad_len)` —
/// `ciphercommon_gcm_hw.c:19-24`. `CRYPTO_gcm128_aad` answers 0 on success, so this is its `== 0`.
///
/// # Safety
/// The `PROV_GCM_HW::aadupdate` contract.
unsafe fn ossl_gcm_aad_update(ctx: *mut ProvGcmCtx, aad: *const c_uchar, aad_len: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { c_int::from(CRYPTO_gcm128_aad(ptr::addr_of_mut!((*ctx).gcm), aad, aad_len) == 0) }
}

/// `int ossl_gcm_cipher_update(PROV_GCM_CTX *ctx, const unsigned char *in, size_t len, unsigned
/// char *out)` — `ciphercommon_gcm_hw.c:26-38`.
///
/// # Safety
/// The `PROV_GCM_HW::cipherupdate` contract.
unsafe fn ossl_gcm_cipher_update(
    ctx: *mut ProvGcmCtx,
    in_: *const c_uchar,
    len: usize,
    out: *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if (*ctx).bits.enc() != 0 {
            if CRYPTO_gcm128_encrypt(ptr::addr_of_mut!((*ctx).gcm), in_, out, len) != 0 {
                return 0;
            }
        } else if CRYPTO_gcm128_decrypt(ptr::addr_of_mut!((*ctx).gcm), in_, out, len) != 0 {
            return 0;
        }
        1
    }
}

/// `int ossl_gcm_cipher_final(PROV_GCM_CTX *ctx, unsigned char *tag)` —
/// `ciphercommon_gcm_hw.c:40-51`. On encryption the tag is produced and `taglen` becomes sixteen;
/// on decryption the expected tag in `tag` is verified against `ctx->taglen` bytes.
///
/// # Safety
/// The `PROV_GCM_HW::cipherfinal` contract.
unsafe fn ossl_gcm_cipher_final(ctx: *mut ProvGcmCtx, tag: *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if (*ctx).bits.enc() != 0 {
            CRYPTO_gcm128_tag(ptr::addr_of_mut!((*ctx).gcm), tag, GCM_TAG_MAX_SIZE);
            (*ctx).taglen = GCM_TAG_MAX_SIZE;
        } else if CRYPTO_gcm128_finish(ptr::addr_of_mut!((*ctx).gcm), tag, (*ctx).taglen) != 0 {
            return 0;
        }
        1
    }
}

/// `int ossl_gcm_one_shot(...)` — `ciphercommon_gcm_hw.c:53-68`, the TLS-record entry point.
///
/// # Safety
/// The `PROV_GCM_HW::oneshot` contract.
#[allow(clippy::too_many_arguments)]
unsafe fn ossl_gcm_one_shot(
    ctx: *mut ProvGcmCtx,
    aad: *mut c_uchar,
    aad_len: usize,
    in_: *const c_uchar,
    in_len: usize,
    out: *mut c_uchar,
    tag: *mut c_uchar,
    _tag_len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ret = 0;

        /* Use saved AAD. */
        let hw = (*ctx).hw;
        if ((*hw).aadupdate)(ctx, aad, aad_len) == 0 {
            return ret;
        }
        if ((*hw).cipherupdate)(ctx, in_, in_len, out) == 0 {
            return ret;
        }
        (*ctx).taglen = GCM_TAG_MAX_SIZE;
        if ((*hw).cipherfinal)(ctx, tag) == 0 {
            return ret;
        }
        ret = 1;
        ret
    }
}

// ---------------------------------------------------------------------------------------------
// `cipher_aes_gcm.c` / `cipher_aes_gcm_hw.c` — the AES arm
// ---------------------------------------------------------------------------------------------

/// `PROV_AES_GCM_CTX` — `cipher_aes_gcm.h:15-46`.
///
/// The `plat` union is a bare `int dummy` in this profile (the s390x KMA arm is not compiled); it
/// is the last four bytes of the measured **960**-byte allocation.
#[repr(C)]
pub(crate) struct ProvAesGcmCtx {
    /// `PROV_GCM_CTX base`.
    pub base: ProvGcmCtx,
    /// `union { OSSL_UNION_ALIGN; AES_KEY ks; } ks`.
    pub ks: AesKeyUnion,
    /// `union { int dummy; ... } plat`. Read by nothing in this profile.
    #[allow(dead_code)] // size-only member: the last four bytes of the allocation request
    pub plat: c_int,
}

/// `aes_gcm_initkey` — `cipher_aes_gcm_hw.c:20-59`'s portable arm, the
/// `GCM_HW_SET_KEY_CTR_FN(AES_set_encrypt_key, AES_encrypt, NULL)` expansion (`AES_CTR_ASM` is not
/// defined on this host, `crypto/aes/build.info:30,55`), so `ctx->ctr` is NULL.
///
/// # Safety
/// `ctx` is a `PROV_AES_GCM_CTX`; `key` is readable for `keylen` bytes.
unsafe fn aes_gcm_initkey(ctx: *mut ProvGcmCtx, key: *const c_uchar, keylen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let actx = ctx.cast::<ProvAesGcmCtx>();
        let ks = ptr::addr_of_mut!((*actx).ks.ks);

        AES_set_encrypt_key(key, (keylen * 8) as c_int, ks);
        CRYPTO_gcm128_init(ptr::addr_of_mut!((*ctx).gcm), ks.cast(), aes_block_encrypt);
        (*ctx).ctr = None;
        (*ctx).bits.set_key_set(true);
        1
    }
}

/// `generic_aes_gcm_cipher_update` — `cipher_aes_gcm_hw.c:61-124`'s portable arm (the
/// `AES_GCM_ASM` bulk arms are not compiled). It dispatches on `ctx->ctr`, which this profile
/// leaves NULL; the `_ctr32` branch is kept because it is the C body's and the crate's `_ctr32`
/// entry point accepts its `ctr128_f`.
///
/// # Safety
/// The `PROV_GCM_HW::cipherupdate` contract.
unsafe fn generic_aes_gcm_cipher_update(
    ctx: *mut ProvGcmCtx,
    in_: *const c_uchar,
    len: usize,
    out: *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let gcm = ptr::addr_of_mut!((*ctx).gcm);
        if (*ctx).bits.enc() != 0 {
            if let Some(ctr) = (*ctx).ctr {
                if CRYPTO_gcm128_encrypt_ctr32(gcm, in_, out, len, ctr) != 0 {
                    return 0;
                }
            } else if CRYPTO_gcm128_encrypt(gcm, in_, out, len) != 0 {
                return 0;
            }
        } else if let Some(ctr) = (*ctx).ctr {
            if CRYPTO_gcm128_decrypt_ctr32(gcm, in_, out, len, ctr) != 0 {
                return 0;
            }
        } else if CRYPTO_gcm128_decrypt(gcm, in_, out, len) != 0 {
            return 0;
        }
        1
    }
}

/// `static const PROV_GCM_HW aes_gcm` — `cipher_aes_gcm_hw.c:126-133`.
static AES_GCM_HW: ProvGcmHw = ProvGcmHw {
    setkey: aes_gcm_initkey,
    setiv: ossl_gcm_setiv,
    aadupdate: ossl_gcm_aad_update,
    cipherupdate: generic_aes_gcm_cipher_update,
    cipherfinal: ossl_gcm_cipher_final,
    oneshot: ossl_gcm_one_shot,
};

/// `const PROV_GCM_HW *ossl_prov_aes_hw_gcm(size_t keybits)` — `cipher_aes_gcm_hw.c:150-153`'s
/// portable arm; the `.inc` arms this profile declines all answer method tables built from the
/// same C functions.
///
/// # Safety
/// Always safe; a uniform signature the hw contract requires.
unsafe fn ossl_prov_aes_hw_gcm(_keybits: usize) -> *const ProvGcmHw {
    ptr::addr_of!(AES_GCM_HW)
}

/// `aes_gcm_newctx` — `cipher_aes_gcm.c:23-35`.
///
/// # Safety
/// The dispatch contract.
unsafe fn aes_gcm_newctx(provctx: *mut c_void, keybits: usize) -> *mut c_void {
    // SAFETY: the caller's contract; `ossl_gcm_initctx` writes only within the allocation.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let ctx = CRYPTO_zalloc(core::mem::size_of::<ProvAesGcmCtx>(), FILE_AES_GCM, LINE);
        if !ctx.is_null() {
            ossl_gcm_initctx(
                provctx,
                ctx.cast::<ProvGcmCtx>(),
                keybits,
                ossl_prov_aes_hw_gcm(keybits),
            );
        }
        ctx
    }
}

/// `aes_gcm_dupctx` — `cipher_aes_gcm.c:37-53`. The shallow copy's `gcm.key` still points at the
/// *original* schedule, so it is repaired to the copy's own.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_gcm_dupctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ctx = provctx.cast::<ProvAesGcmCtx>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        let dupctx = CRYPTO_memdup(
            provctx,
            core::mem::size_of::<ProvAesGcmCtx>(),
            FILE_AES_GCM,
            LINE,
        );
        if !dupctx.is_null() {
            let dup = dupctx.cast::<ProvAesGcmCtx>();
            let gcm = ptr::addr_of_mut!((*dup).base.gcm);
            if !gcm_key_is_null(gcm) {
                gcm_repoint_key(gcm, ptr::addr_of_mut!((*dup).ks).cast());
            }
        }
        dupctx
    }
}

/// `aes_gcm_freectx` — `cipher_aes_gcm.c:55-61`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_gcm_freectx(vctx: *mut c_void) {
    // SAFETY: the context is the one `aes_gcm_newctx` allocated.
    unsafe {
        CRYPTO_clear_free(
            vctx,
            core::mem::size_of::<ProvAesGcmCtx>(),
            FILE_AES_GCM,
            LINE,
        )
    };
}

// ---------------------------------------------------------------------------------------------
// `cipher_aria_gcm*.c` — the ARIA arm
// ---------------------------------------------------------------------------------------------

/// `PROV_ARIA_GCM_CTX` — `cipher_aria_gcm.h:9-16`. Unlike the AES context there is no `plat`
/// member. The measured authority size is **984**, which this crate reproduces with the
/// eight-aligned `GcmCtx` base (`ks` at 704, the 276-byte `ARIA_KEY` rounded to the base's
/// alignment).
#[repr(C)]
pub(crate) struct ProvAriaGcmCtx {
    /// `PROV_GCM_CTX base`.
    pub base: ProvGcmCtx,
    /// `union { OSSL_UNION_ALIGN; ARIA_KEY ks; } ks`.
    pub ks: crate::aria::AriaKey,
}

/// `aria_gcm_initkey` — `cipher_aria_gcm_hw.c:16-24`, the `GCM_HW_SET_KEY_CTR_FN` expansion with
/// ARIA's schedule setter and no CTR block (so `ctx->ctr` is NULL). The schedule setter's return
/// value is ignored, as the authority ignores it.
///
/// # Safety
/// `ctx` is a `PROV_ARIA_GCM_CTX`; `key` is readable for `keylen` bytes.
unsafe fn aria_gcm_initkey(ctx: *mut ProvGcmCtx, key: *const c_uchar, keylen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let actx = ctx.cast::<ProvAriaGcmCtx>();
        let ks: *mut crate::aria::AriaKey = ptr::addr_of_mut!((*actx).ks);

        crate::aria::ossl_aria_set_encrypt_key(key, (keylen * 8) as c_int, ks);
        CRYPTO_gcm128_init(ptr::addr_of_mut!((*ctx).gcm), ks.cast(), aria_block_encrypt);
        (*ctx).ctr = None;
        (*ctx).bits.set_key_set(true);
        1
    }
}

/// `static const PROV_GCM_HW aria_gcm` — `cipher_aria_gcm_hw.c:26-33`.
static ARIA_GCM_HW: ProvGcmHw = ProvGcmHw {
    setkey: aria_gcm_initkey,
    setiv: ossl_gcm_setiv,
    aadupdate: ossl_gcm_aad_update,
    cipherupdate: ossl_gcm_cipher_update,
    cipherfinal: ossl_gcm_cipher_final,
    oneshot: ossl_gcm_one_shot,
};

/// `const PROV_GCM_HW *ossl_prov_aria_hw_gcm(size_t keybits)` — `cipher_aria_gcm_hw.c:34-37`.
/// ARIA has one GCM table and ignores `keybits`.
///
/// # Safety
/// Always safe; a uniform signature the hw contract requires.
unsafe fn ossl_prov_aria_hw_gcm(_keybits: usize) -> *const ProvGcmHw {
    ptr::addr_of!(ARIA_GCM_HW)
}

/// `aria_gcm_newctx` — `cipher_aria_gcm.c:16-28`.
///
/// # Safety
/// The dispatch contract.
unsafe fn aria_gcm_newctx(provctx: *mut c_void, keybits: usize) -> *mut c_void {
    // SAFETY: the caller's contract; `ossl_gcm_initctx` writes only within the allocation.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let ctx = CRYPTO_zalloc(core::mem::size_of::<ProvAriaGcmCtx>(), FILE_ARIA_GCM, LINE);
        if !ctx.is_null() {
            ossl_gcm_initctx(
                provctx,
                ctx.cast::<ProvGcmCtx>(),
                keybits,
                ossl_prov_aria_hw_gcm(keybits),
            );
        }
        ctx
    }
}

/// `aria_gcm_dupctx` — `cipher_aria_gcm.c:30-43`. Unlike the AES arm this one does not test
/// `ossl_prov_is_running`, which is why the crate does not either.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aria_gcm_dupctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = provctx.cast::<ProvAriaGcmCtx>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        let dupctx = CRYPTO_memdup(
            provctx,
            core::mem::size_of::<ProvAriaGcmCtx>(),
            FILE_ARIA_GCM,
            LINE,
        );
        if !dupctx.is_null() {
            let dup = dupctx.cast::<ProvAriaGcmCtx>();
            let gcm = ptr::addr_of_mut!((*dup).base.gcm);
            if !gcm_key_is_null(gcm) {
                gcm_repoint_key(gcm, ptr::addr_of_mut!((*dup).ks).cast());
            }
        }
        dupctx
    }
}

/// `aria_gcm_freectx` — `cipher_aria_gcm.c:45-51`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aria_gcm_freectx(vctx: *mut c_void) {
    // SAFETY: the context is the one `aria_gcm_newctx` allocated.
    unsafe {
        CRYPTO_clear_free(
            vctx,
            core::mem::size_of::<ProvAriaGcmCtx>(),
            FILE_ARIA_GCM,
            LINE,
        )
    };
}

// ---------------------------------------------------------------------------------------------
// `cipher_sm4_gcm*.c` — the SM4 arm
// ---------------------------------------------------------------------------------------------

/// `PROV_SM4_GCM_CTX` — `cipher_sm4_gcm.h:9-15`. The measured authority size is **832**, which
/// this crate reproduces (128-byte `SM4_KEY`, no alignment slack).
#[repr(C)]
pub(crate) struct ProvSm4GcmCtx {
    /// `PROV_GCM_CTX base`.
    pub base: ProvGcmCtx,
    /// `union { OSSL_UNION_ALIGN; SM4_KEY ks; } ks`.
    pub ks: crate::sm4::Sm4Key,
}

/// `sm4_gcm_initkey` — `cipher_sm4_gcm_hw.c:217-252`'s portable arm, the
/// `SM4_GCM_HW_SET_KEY_CTR_FN(ossl_sm4_set_key, ossl_sm4_encrypt, NULL)` expansion.
///
/// # Safety
/// `ctx` is a `PROV_SM4_GCM_CTX`; `key` is readable for sixteen bytes.
unsafe fn sm4_gcm_initkey(ctx: *mut ProvGcmCtx, key: *const c_uchar, _keylen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let actx = ctx.cast::<ProvSm4GcmCtx>();
        let ks: *mut crate::sm4::Sm4Key = ptr::addr_of_mut!((*actx).ks);

        crate::sm4::ossl_sm4_set_key(key, ks);
        CRYPTO_gcm128_init(ptr::addr_of_mut!((*ctx).gcm), ks.cast(), sm4_block_encrypt);
        (*ctx).ctr = None;
        (*ctx).bits.set_key_set(true);
        1
    }
}

/// `hw_gcm_cipher_update` — `cipher_sm4_gcm_hw.c:254-275`: the same `ctx->ctr` dispatch as the AES
/// arm, with no `AES_GCM_ASM` bulk arm.
///
/// # Safety
/// The `PROV_GCM_HW::cipherupdate` contract.
unsafe fn sm4_gcm_cipher_update(
    ctx: *mut ProvGcmCtx,
    in_: *const c_uchar,
    len: usize,
    out: *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let gcm = ptr::addr_of_mut!((*ctx).gcm);
        if (*ctx).bits.enc() != 0 {
            if let Some(ctr) = (*ctx).ctr {
                if CRYPTO_gcm128_encrypt_ctr32(gcm, in_, out, len, ctr) != 0 {
                    return 0;
                }
            } else if CRYPTO_gcm128_encrypt(gcm, in_, out, len) != 0 {
                return 0;
            }
        } else if let Some(ctr) = (*ctx).ctr {
            if CRYPTO_gcm128_decrypt_ctr32(gcm, in_, out, len, ctr) != 0 {
                return 0;
            }
        } else if CRYPTO_gcm128_decrypt(gcm, in_, out, len) != 0 {
            return 0;
        }
        1
    }
}

/// `static const PROV_GCM_HW sm4_gcm` — `cipher_sm4_gcm_hw.c:277-284`.
static SM4_GCM_HW: ProvGcmHw = ProvGcmHw {
    setkey: sm4_gcm_initkey,
    setiv: ossl_gcm_setiv,
    aadupdate: ossl_gcm_aad_update,
    cipherupdate: sm4_gcm_cipher_update,
    cipherfinal: ossl_gcm_cipher_final,
    oneshot: ossl_gcm_one_shot,
};

/// `const PROV_GCM_HW *ossl_prov_sm4_hw_gcm(size_t keybits)` — `cipher_sm4_gcm_hw.c:291-294`'s
/// portable arm; the `x86_64` and `rv64i` `.inc` arms this profile declines answer method tables
/// built from the same C functions.
///
/// # Safety
/// Always safe; a uniform signature the hw contract requires.
unsafe fn ossl_prov_sm4_hw_gcm(_keybits: usize) -> *const ProvGcmHw {
    ptr::addr_of!(SM4_GCM_HW)
}

/// `sm4_gcm_newctx` — `cipher_sm4_gcm.c:18-30`.
///
/// # Safety
/// The dispatch contract.
unsafe fn sm4_gcm_newctx(provctx: *mut c_void, keybits: usize) -> *mut c_void {
    // SAFETY: the caller's contract; `ossl_gcm_initctx` writes only within the allocation.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let ctx = CRYPTO_zalloc(core::mem::size_of::<ProvSm4GcmCtx>(), FILE_SM4_GCM, LINE);
        if !ctx.is_null() {
            ossl_gcm_initctx(
                provctx,
                ctx.cast::<ProvGcmCtx>(),
                keybits,
                ossl_prov_sm4_hw_gcm(keybits),
            );
        }
        ctx
    }
}

/// `sm4_gcm_dupctx` — `cipher_sm4_gcm.c:32-45`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sm4_gcm_dupctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = provctx.cast::<ProvSm4GcmCtx>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        let dupctx = CRYPTO_memdup(
            provctx,
            core::mem::size_of::<ProvSm4GcmCtx>(),
            FILE_SM4_GCM,
            LINE,
        );
        if !dupctx.is_null() {
            let dup = dupctx.cast::<ProvSm4GcmCtx>();
            let gcm = ptr::addr_of_mut!((*dup).base.gcm);
            if !gcm_key_is_null(gcm) {
                gcm_repoint_key(gcm, ptr::addr_of_mut!((*dup).ks).cast());
            }
        }
        dupctx
    }
}

/// `sm4_gcm_freectx` — `cipher_sm4_gcm.c:47-53`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sm4_gcm_freectx(vctx: *mut c_void) {
    // SAFETY: the context is the one `sm4_gcm_newctx` allocated.
    unsafe {
        CRYPTO_clear_free(
            vctx,
            core::mem::size_of::<ProvSm4GcmCtx>(),
            FILE_SM4_GCM,
            LINE,
        )
    };
}

// ---------------------------------------------------------------------------------------------
// The block functions the three `initkey`s hand to `CRYPTO_gcm128_init`
// ---------------------------------------------------------------------------------------------

/// `AES_encrypt` as the GCM block function — `aes_gcm_initkey`'s `(block128_f)AES_encrypt`.
///
/// # Safety
/// `key` is an `AES_KEY *`; `in_`/`out` are sixteen-byte blocks.
unsafe extern "C" fn aes_block_encrypt(in_: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract.
    unsafe { AES_encrypt(in_, out, key.cast::<AesKey>()) };
}

/// `ossl_aria_encrypt` as the GCM block function — `aria_gcm_initkey`'s
/// `(block128_f)ossl_aria_encrypt`.
///
/// # Safety
/// `key` is an `ARIA_KEY *`; `in_`/`out` are sixteen-byte blocks.
unsafe extern "C" fn aria_block_encrypt(in_: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract.
    unsafe { crate::aria::ossl_aria_encrypt(in_, out, key.cast::<crate::aria::AriaKey>()) };
}

/// `ossl_sm4_encrypt` as the GCM block function — `sm4_gcm_initkey`'s
/// `(block128_f)ossl_sm4_encrypt`.
///
/// # Safety
/// `key` is an `SM4_KEY *`; `in_`/`out` are sixteen-byte blocks.
unsafe extern "C" fn sm4_block_encrypt(in_: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract.
    unsafe { crate::sm4::ossl_sm4_encrypt(in_, out, key.cast::<crate::sm4::Sm4Key>()) };
}

// ---------------------------------------------------------------------------------------------
// `prov/ciphercommon_aead.h:18-67` — the dispatch tables
// ---------------------------------------------------------------------------------------------

/// The allocation-tracking `file` argument `ciphercommon.c`'s one allocation uses: a `.c.in`
/// template the build expands into the build tree, so it carries no source-tree prefix.
const LINE: c_int = 0;

/// `IMPLEMENT_aead_cipher` — `prov/ciphercommon_aead.h:18-67`, the GCM rows' dispatch tables. Each
/// has fourteen entries: `CIPHER` is the shared `ossl_gcm_cipher`, `UPDATE`/`FINAL` the shared
/// stream pair, and `GET_PARAMS` is the row's own `blkbits`/`ivbits` triple.
///
/// As with `ccm_row!`, the three per-family items are parameters because that is exactly what the
/// seven rows differ in; the expansion writes only `pub(crate)` function items and a `'static`
/// table, so no exported symbol is generated.
macro_rules! gcm_row {
    ($newctx:ident, $getparams:ident, $table:ident, $kbits:expr, $newctx_impl:path,
     $freectx:path, $dupctx:path) => {
        unsafe extern "C" fn $newctx(provctx: *mut c_void) -> *mut c_void {
            // SAFETY: the dispatch contract.
            unsafe { $newctx_impl(provctx, $kbits) }
        }

        unsafe extern "C" fn $getparams(params: *mut OsslParam) -> c_int {
            // SAFETY: the dispatch contract.
            unsafe {
                ossl_cipher_generic_get_params(
                    params,
                    EVP_CIPH_GCM_MODE,
                    AEAD_FLAGS,
                    $kbits,
                    GCM_BLOCK_BITS,
                    GCM_IV_BITS,
                )
            }
        }

        pub(crate) static $table: [OsslDispatch; 15] = [
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_NEWCTX,
                function: $newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_FREECTX,
                function: $freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_DUPCTX,
                function: $dupctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_ENCRYPT_INIT,
                function: ossl_gcm_einit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_DECRYPT_INIT,
                function: ossl_gcm_dinit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_UPDATE,
                function: ossl_gcm_stream_update as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_FINAL,
                function: ossl_gcm_stream_final as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_CIPHER,
                function: ossl_gcm_cipher as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GET_PARAMS,
                function: $getparams as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
                function: ossl_gcm_get_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                function: ossl_gcm_set_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
                function: ossl_cipher_generic_gettable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
                function: ossl_gcm_gettable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                function: ossl_gcm_settable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

// `IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, <kbits>, 8, 96)` — `cipher_aes_gcm.c:63-68`.
gcm_row!(
    aes128gcm_newctx,
    aes128gcm_get_params,
    AES128GCM_FUNCTIONS,
    128,
    aes_gcm_newctx,
    aes_gcm_freectx,
    aes_gcm_dupctx
);
gcm_row!(
    aes192gcm_newctx,
    aes192gcm_get_params,
    AES192GCM_FUNCTIONS,
    192,
    aes_gcm_newctx,
    aes_gcm_freectx,
    aes_gcm_dupctx
);
gcm_row!(
    aes256gcm_newctx,
    aes256gcm_get_params,
    AES256GCM_FUNCTIONS,
    256,
    aes_gcm_newctx,
    aes_gcm_freectx,
    aes_gcm_dupctx
);

// `IMPLEMENT_aead_cipher(aria, gcm, GCM, AEAD_FLAGS, <kbits>, 8, 96)` — `cipher_aria_gcm.c:53-58`.
gcm_row!(
    aria128gcm_newctx,
    aria128gcm_get_params,
    ARIA128GCM_FUNCTIONS,
    128,
    aria_gcm_newctx,
    aria_gcm_freectx,
    aria_gcm_dupctx
);
gcm_row!(
    aria192gcm_newctx,
    aria192gcm_get_params,
    ARIA192GCM_FUNCTIONS,
    192,
    aria_gcm_newctx,
    aria_gcm_freectx,
    aria_gcm_dupctx
);
gcm_row!(
    aria256gcm_newctx,
    aria256gcm_get_params,
    ARIA256GCM_FUNCTIONS,
    256,
    aria_gcm_newctx,
    aria_gcm_freectx,
    aria_gcm_dupctx
);

// `IMPLEMENT_aead_cipher(sm4, gcm, GCM, AEAD_FLAGS, 128, 8, 96)` — `cipher_sm4_gcm.c:53`.
gcm_row!(
    sm4128gcm_newctx,
    sm4128gcm_get_params,
    SM4128GCM_FUNCTIONS,
    128,
    sm4_gcm_newctx,
    sm4_gcm_freectx,
    sm4_gcm_dupctx
);

/// `ctx->gcm.key != NULL` — the guard the three `dupctx` bodies test before repairing the key.
///
/// # Safety
/// `gcm` points at a live `GcmCtx`.
unsafe fn gcm_key_is_null(gcm: *const GcmCtx) -> bool {
    // SAFETY: the caller's contract; the mirror is layout-identical (the unit test pins it).
    unsafe { (*gcm.cast::<GcmCtxMirror>()).key.is_null() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Every provider GCM context, measured against the authority's own compiler.** The numbers
    /// are from a program compiled with `courts/layout/README.md`'s include set against the pinned
    /// build's internal headers; the allocation request is what a `CRYPTO_set_mem_functions`
    /// application's allocator receives, so the size is contract.
    ///
    /// All four match the authority: `PROV_GCM_CTX` at 704, `PROV_AES_GCM_CTX` at 960,
    /// `PROV_SM4_GCM_CTX` at 832 and `PROV_ARIA_GCM_CTX` at 984. The `iv`/`buf`/`libctx`/`hw`/`ctr`
    /// offsets are the authority's own; `gcm` sits at 248 and `gcm_reserve` carries the rest of the
    /// authority's 448-byte region. The crate's `GcmCtx` carries its `H`/`Xi` as `[u64; 2]` so it
    /// has the authority's eight-byte alignment rather than the sixteen a `u128` would force.
    #[test]
    fn the_gcm_contexts_are_the_authoritys_sizes() {
        assert_eq!(core::mem::size_of::<ProvGcmCtx>(), 704);
        assert_eq!(core::mem::offset_of!(ProvGcmCtx, mode), 0);
        assert_eq!(core::mem::offset_of!(ProvGcmCtx, keylen), 8);
        assert_eq!(core::mem::offset_of!(ProvGcmCtx, iv_state), 80);
        assert_eq!(core::mem::offset_of!(ProvGcmCtx, bits), 84);
        assert_eq!(core::mem::offset_of!(ProvGcmCtx, iv), 85);
        assert_eq!(core::mem::offset_of!(ProvGcmCtx, buf), 213);
        assert_eq!(core::mem::offset_of!(ProvGcmCtx, libctx), 232);
        assert_eq!(core::mem::offset_of!(ProvGcmCtx, hw), 240);
        assert_eq!(core::mem::offset_of!(ProvGcmCtx, gcm), 248);
        assert_eq!(core::mem::offset_of!(ProvGcmCtx, gcm_reserve), 400);
        assert_eq!(core::mem::offset_of!(ProvGcmCtx, ctr), 696);
        // The crate's GCM128_CONTEXT model, at the authority's eight-byte alignment.
        assert_eq!(core::mem::size_of::<GcmCtx>(), 152);
        assert_eq!(core::mem::offset_of!(GcmCtxMirror, key), 144);
        assert_eq!(core::mem::size_of::<GcmCtxMirror>(), 152);

        assert_eq!(core::mem::size_of::<ProvAesGcmCtx>(), 960);
        assert_eq!(core::mem::offset_of!(ProvAesGcmCtx, ks), 704);
        assert_eq!(core::mem::size_of::<ProvSm4GcmCtx>(), 832);
        assert_eq!(core::mem::offset_of!(ProvSm4GcmCtx, ks), 704);
        assert_eq!(core::mem::size_of::<ProvAriaGcmCtx>(), 984);
        assert_eq!(core::mem::offset_of!(ProvAriaGcmCtx, ks), 704);

        assert_eq!(core::mem::size_of::<ProvGcmHw>(), 48);
        assert_eq!(core::mem::size_of::<GcmFlags>(), 1);
    }
}
