//! Phase 13.6c — `crypto/evp/e_chacha20_poly1305.c`: the deprecated `EVP_chacha20` and
//! `EVP_chacha20_poly1305` statics.
//!
//! `EVP_chacha20()` and `EVP_chacha20_poly1305()` are one line each — `return &chacha20;` and
//! `return &chacha20_poly1305;` (`e_chacha20_poly1305.c:146-149`, `:625-628`) — over two
//! `static EVP_CIPHER`s whose legacy halves are the `chacha_init_key`/`chacha_cipher` pair and the
//! `chacha20_poly1305_*` AEAD callbacks. This module transcribes both objects field for field and
//! the callbacks with them.
//!
//! ## The ChaCha20 primitive takes host-order words, and `chacha_init_key` collects them
//!
//! `EVP_CHACHA_KEY.key` is `unsigned int d[8]` (`e_chacha20_poly1305.c:25`), not a byte vector:
//! `chacha_init_key` reads the caller's bytes through `CHACHA_U8TOU32` (`:44-51`) and the cipher
//! hands the words straight to `ChaCha20_ctr32`, whose own module (`src/chacha.rs`) records why.
//!
//! ## The `XOR128_HELPERS` TLS arm is not modelled
//!
//! `chacha20_poly1305_tls_cipher` selects the interleaved `xor128_*` arm only under
//! `POLY1305_ASM && x86_64` (`e_chacha20_poly1305.c:207-211`), which calls two perlasm helpers
//! this crate does not carry. The `#else` arm (`:254-288`) is the portable transcription here.
//! The TLS arms themselves are reachable only through `EVP_CTRL_AEAD_TLS1_AAD`, which the court
//! does not drive (the CBC-HMAC TLS-record arms are `RT-CIPHER`'s); the AEAD sequence drives the
//! non-TLS path.
//!
//! ## These objects are carriers, and the library replaces them before any callback runs
//!
//! `evp_cipher_init_internal` (`src/evp/cipher_ctx.rs`) opens with the test the AES slice's module
//! doc states: a method whose `prov` is NULL is **fetched by short name** and `type` is rebound to
//! the provider method. Both objects have no provider, so a caller that hands either to
//! `EVP_EncryptInit_ex` runs the default provider's `ChaCha20`/`ChaCha20-Poly1305` row
//! (`defltprov.c:324-329`), not these callbacks. The callbacks are transcribed for faithfulness —
//! an engine is the only reachable caller.
//!
//! ## What this module does not define
//!
//! The `ChaCha20_ctr32` and `Poly1305_*` primitives are Phase 8's (`src/chacha.rs`,
//! `src/mac/poly1305.rs`). Only the two accessors `forensics/atlas/export-defining-units.json`
//! assigns to `e_chacha20_poly1305.c` are exported here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;

use crate::chacha::{u8tou32, ChaCha20_ctr32, CHACHA_BLK_SIZE, CHACHA_CTR_SIZE, CHACHA_KEY_SIZE};
use crate::evp::cipher::{CipherLegacyCtrlFn, CipherLegacyDoFn, CipherLegacyInitFn, EvpCipher};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_cipher_data, EVP_CIPHER_CTX_is_encrypting, EvpCipherCtx,
};
use crate::mac::poly1305::{
    Poly1305, Poly1305_Final, Poly1305_Init, Poly1305_Update, Poly1305_ctx_size,
    POLY1305_BLOCK_SIZE,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_memcmp, CRYPTO_memdup, CRYPTO_zalloc, OPENSSL_cleanse};
use crate::runtime::obj::{NID_chacha20, NID_chacha20_poly1305};

/// `EVP_CIPH_CUSTOM_IV` — `include/openssl/evp.h:327`.
const EVP_CIPH_CUSTOM_IV: c_ulong = 0x10;
/// `EVP_CIPH_ALWAYS_CALL_INIT` — `include/openssl/evp.h:329`.
const EVP_CIPH_ALWAYS_CALL_INIT: c_ulong = 0x20;
/// `EVP_CIPH_CTRL_INIT` — `include/openssl/evp.h:331`.
const EVP_CIPH_CTRL_INIT: c_ulong = 0x40;
/// `EVP_CIPH_CUSTOM_COPY` — `include/openssl/evp.h:339`.
const EVP_CIPH_CUSTOM_COPY: c_ulong = 0x400;
/// `EVP_CIPH_CUSTOM_IV_LENGTH` — `include/openssl/evp.h:341`.
const EVP_CIPH_CUSTOM_IV_LENGTH: c_ulong = 0x800;
/// `EVP_CIPH_FLAG_CUSTOM_CIPHER` — `include/openssl/evp.h:356`.
const EVP_CIPH_FLAG_CUSTOM_CIPHER: c_ulong = 0x100000;
/// `EVP_CIPH_FLAG_AEAD_CIPHER` — `include/openssl/evp.h:357`.
const EVP_CIPH_FLAG_AEAD_CIPHER: c_ulong = 0x200000;

/// `EVP_CTRL_INIT` — `include/openssl/evp.h:379`.
const EVP_CTRL_INIT: c_int = 0x0;
/// `EVP_CTRL_COPY` — `include/openssl/evp.h:387`.
const EVP_CTRL_COPY: c_int = 0x8;
/// `EVP_CTRL_GET_IVLEN` — `include/openssl/evp.h:442`.
const EVP_CTRL_GET_IVLEN: c_int = 0x25;
/// `EVP_CTRL_AEAD_SET_IVLEN` — `include/openssl/evp.h:388`.
const EVP_CTRL_AEAD_SET_IVLEN: c_int = 0x9;
/// `EVP_CTRL_AEAD_GET_TAG` — `include/openssl/evp.h:389`.
const EVP_CTRL_AEAD_GET_TAG: c_int = 0x10;
/// `EVP_CTRL_AEAD_SET_TAG` — `include/openssl/evp.h:390`.
const EVP_CTRL_AEAD_SET_TAG: c_int = 0x11;
/// `EVP_CTRL_AEAD_SET_IV_FIXED` — `include/openssl/evp.h:391`.
const EVP_CTRL_AEAD_SET_IV_FIXED: c_int = 0x12;
/// `EVP_CTRL_AEAD_TLS1_AAD` — `include/openssl/evp.h:408`.
const EVP_CTRL_AEAD_TLS1_AAD: c_int = 0x16;
/// `EVP_CTRL_AEAD_SET_MAC_KEY` — `include/openssl/evp.h:410`.
const EVP_CTRL_AEAD_SET_MAC_KEY: c_int = 0x17;

/// `EVP_AEAD_TLS1_AAD_LEN` — `include/openssl/evp.h:461`.
const EVP_AEAD_TLS1_AAD_LEN: c_int = 13;
/// `CHACHA20_POLY1305_MAX_IVLEN` — `e_chacha20_poly1305.c:34`.
const CHACHA20_POLY1305_MAX_IVLEN: c_int = 12;
/// `NO_TLS_PAYLOAD_LENGTH` — `e_chacha20_poly1305.c:166`: `(size_t)-1`.
const NO_TLS_PAYLOAD_LENGTH: usize = usize::MAX;

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h`. A method in read-only memory.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `data(ctx)` — `e_chacha20_poly1305.c:32`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX` whose method allocated a `cipher_data` block.
unsafe fn data(ctx: *const EvpCipherCtx) -> *mut EvpChachaKey {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }.cast::<EvpChachaKey>()
}

/// `aead_data(ctx)` — `e_chacha20_poly1305.c:167`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX` whose `cipher_data` is the AEAD block.
unsafe fn aead_data(ctx: *const EvpCipherCtx) -> *mut EvpChachaAeadCtx {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }.cast::<EvpChachaAeadCtx>()
}

/// `POLY1305_ctx(actx)` — `e_chacha20_poly1305.c:168`: the Poly1305 context laid out immediately
/// after the AEAD context.
///
/// # Safety
/// `actx` must point to an allocation of `sizeof(*actx) + Poly1305_ctx_size()` bytes.
unsafe fn poly1305_ctx(actx: *mut EvpChachaAeadCtx) -> *mut Poly1305 {
    // SAFETY: the caller's contract; the offset is the struct's own size.
    unsafe {
        actx.cast::<u8>()
            .add(core::mem::size_of::<EvpChachaAeadCtx>())
            .cast::<Poly1305>()
    }
}

// ---------------------------------------------------------------------------------------------
// The contexts — `e_chacha20_poly1305.c:22-30`, `:154-164`
// ---------------------------------------------------------------------------------------------

/// `EVP_CHACHA_KEY` — `e_chacha20_poly1305.c:22-30`.
pub struct EvpChachaKey {
    /// `unsigned int d[CHACHA_KEY_SIZE / 4]` — the key as eight host-order words.
    pub d: [c_uint; CHACHA_KEY_SIZE / 4],
    /// `unsigned int counter[CHACHA_CTR_SIZE / 4]`.
    pub counter: [c_uint; CHACHA_CTR_SIZE / 4],
    /// `unsigned char buf[CHACHA_BLK_SIZE]`.
    pub buf: [c_uchar; CHACHA_BLK_SIZE],
    /// `unsigned int partial_len`.
    pub partial_len: c_uint,
}

/// The `len` sub-structure of `EVP_CHACHA_AEAD_CTX` — `e_chacha20_poly1305.c:159-161`.
#[repr(C)]
pub struct EvpChachaAeadLen {
    /// `uint64_t aad`.
    pub aad: u64,
    /// `uint64_t text`.
    pub text: u64,
}

/// `EVP_CHACHA_AEAD_CTX` — `e_chacha20_poly1305.c:154-164`.
pub struct EvpChachaAeadCtx {
    /// `EVP_CHACHA_KEY key`.
    pub key: EvpChachaKey,
    /// `unsigned int nonce[12 / 4]`.
    pub nonce: [c_uint; 3],
    /// `unsigned char tag[POLY1305_BLOCK_SIZE]`.
    pub tag: [c_uchar; POLY1305_BLOCK_SIZE],
    /// `unsigned char tls_aad[POLY1305_BLOCK_SIZE]`.
    pub tls_aad: [c_uchar; POLY1305_BLOCK_SIZE],
    /// `struct { uint64_t aad, text; } len`.
    pub len: EvpChachaAeadLen,
    /// `int aad`.
    pub aad: c_int,
    /// `int mac_inited`.
    pub mac_inited: c_int,
    /// `int tag_len`.
    pub tag_len: c_int,
    /// `int nonce_len`.
    pub nonce_len: c_int,
    /// `size_t tls_payload_length`.
    pub tls_payload_length: usize,
}

// ---------------------------------------------------------------------------------------------
// The ChaCha20 stream callbacks — `e_chacha20_poly1305.c:36-127`
// ---------------------------------------------------------------------------------------------

/// `chacha_init_key` — `e_chacha20_poly1305.c:36-56`.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn chacha_init_key(
    ctx: *mut c_void,
    user_key: *const u8,
    iv: *const u8,
    _enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { data(ctx) };
    if !user_key.is_null() {
        let mut i = 0usize;
        while i < CHACHA_KEY_SIZE {
            // SAFETY: `user_key` is readable for thirty-two bytes and `i` is in range.
            let w = unsafe { u8tou32(core::slice::from_raw_parts(user_key.add(i), 4)) };
            // SAFETY: `key` is the context's own block and `i / 4` is in range.
            unsafe { (*key).d[i / 4] = w };
            i += 4;
        }
    }
    if !iv.is_null() {
        let mut i = 0usize;
        while i < CHACHA_CTR_SIZE {
            // SAFETY: `iv` is readable for sixteen bytes and `i` is in range.
            let w = unsafe { u8tou32(core::slice::from_raw_parts(iv.add(i), 4)) };
            // SAFETY: `key` is the context's own block and `i / 4` is in range.
            unsafe { (*key).counter[i / 4] = w };
            i += 4;
        }
    }
    // SAFETY: `key` is the context's own block.
    unsafe { (*key).partial_len = 0 };
    1
}

/// `chacha_cipher` — `e_chacha20_poly1305.c:58-127`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn chacha_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    inp: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { data(ctx) };
    let mut out = out;
    let mut inp = inp;
    let mut len = len;
    // SAFETY: `key` is the context's own block.
    let mut n = unsafe { (*key).partial_len };
    if n != 0 {
        while len != 0 && n < CHACHA_BLK_SIZE as c_uint {
            // SAFETY: `out`/`inp` are valid for at least the bytes consumed and `key->buf[n]`.
            unsafe {
                *out = *inp ^ (*key).buf[n as usize];
                out = out.add(1);
                inp = inp.add(1);
                n += 1;
                len -= 1;
            }
        }
        // SAFETY: `key` is the context's own block.
        unsafe { (*key).partial_len = n };
        if len == 0 {
            return 1;
        }
        if n == CHACHA_BLK_SIZE as c_uint {
            // SAFETY: `key` is the context's own block.
            unsafe {
                (*key).partial_len = 0;
                (*key).counter[0] = (*key).counter[0].wrapping_add(1);
                if (*key).counter[0] == 0 {
                    (*key).counter[1] = (*key).counter[1].wrapping_add(1);
                }
            }
        }
    }
    let rem = (len % CHACHA_BLK_SIZE) as c_uint;
    len -= rem as usize;
    // SAFETY: `key` is the context's own block.
    let mut ctr32 = unsafe { (*key).counter[0] };
    while len >= CHACHA_BLK_SIZE {
        let mut blocks = len / CHACHA_BLK_SIZE;
        if core::mem::size_of::<usize>() > core::mem::size_of::<c_uint>() && blocks > (1usize << 28)
        {
            blocks = 1usize << 28;
        }
        ctr32 = ctr32.wrapping_add(blocks as c_uint);
        if ctr32 < blocks as c_uint {
            blocks -= ctr32 as usize;
            ctr32 = 0;
        }
        let nbytes = blocks * CHACHA_BLK_SIZE;
        // SAFETY: `out`/`inp` are valid for `nbytes`, and `key` holds the key and counter.
        unsafe { ChaCha20_ctr32(out, inp, nbytes, (*key).d.as_ptr(), (*key).counter.as_ptr()) };
        len -= nbytes;
        // SAFETY: the chunk is within the caller's buffers.
        unsafe {
            inp = inp.add(nbytes);
            out = out.add(nbytes);
        }
        // SAFETY: `key` is the context's own block.
        unsafe {
            (*key).counter[0] = ctr32;
            if ctr32 == 0 {
                (*key).counter[1] = (*key).counter[1].wrapping_add(1);
            }
        }
    }
    if rem != 0 {
        // SAFETY: `key` is the context's own block; the buf is sixty-four bytes.
        unsafe {
            ptr::write_bytes((*key).buf.as_mut_ptr(), 0, CHACHA_BLK_SIZE);
            ChaCha20_ctr32(
                (*key).buf.as_mut_ptr(),
                (*key).buf.as_ptr(),
                CHACHA_BLK_SIZE,
                (*key).d.as_ptr(),
                (*key).counter.as_ptr(),
            );
        }
        let mut i = 0usize;
        while i < rem as usize {
            // SAFETY: `out`/`inp` are valid for `rem` bytes and `buf` for `rem`.
            unsafe { *out.add(i) = *inp.add(i) ^ (*key).buf[i] };
            i += 1;
        }
        // SAFETY: `key` is the context's own block.
        unsafe { (*key).partial_len = rem };
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The Poly1305 AEAD callbacks — `e_chacha20_poly1305.c:170-606`
// ---------------------------------------------------------------------------------------------

/// `chacha20_poly1305_init_key` — `e_chacha20_poly1305.c:170-203`.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn chacha20_poly1305_init_key(
    ctx: *mut c_void,
    inkey: *const u8,
    iv: *const u8,
    enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let actx = unsafe { aead_data(ctx) };
    if inkey.is_null() && iv.is_null() {
        return 1;
    }
    // SAFETY: `actx` is the context's own block.
    unsafe {
        (*actx).len.aad = 0;
        (*actx).len.text = 0;
        (*actx).aad = 0;
        (*actx).mac_inited = 0;
        (*actx).tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
    }
    if !iv.is_null() {
        let mut temp = [0u8; CHACHA_CTR_SIZE];
        // SAFETY: `actx` is live.
        let nonce_len = unsafe { (*actx).nonce_len };
        if nonce_len <= CHACHA_CTR_SIZE as c_int {
            // SAFETY: `iv` is readable for `nonce_len` bytes and `temp` is sixteen bytes.
            unsafe {
                ptr::copy_nonoverlapping(
                    iv,
                    temp.as_mut_ptr().add(CHACHA_CTR_SIZE - nonce_len as usize),
                    nonce_len as usize,
                );
            }
        }
        // SAFETY: `ctx` is live and `temp` is sixteen readable bytes.
        unsafe { chacha_init_key(ctx.cast(), inkey, temp.as_ptr(), enc) };
        // SAFETY: `actx` is live.
        unsafe {
            (*actx).nonce[0] = (*actx).key.counter[1];
            (*actx).nonce[1] = (*actx).key.counter[2];
            (*actx).nonce[2] = (*actx).key.counter[3];
        }
    } else {
        // SAFETY: `ctx` is live and the IV is absent.
        unsafe { chacha_init_key(ctx.cast(), inkey, ptr::null(), enc) };
    }
    1
}

/// `xor128_encrypt_n_pad`/`xor128_decrypt_n_pad`'s absence: the portable TLS arm's `zero` array,
/// `2 * CHACHA_BLK_SIZE` bytes — `e_chacha20_poly1305.c:213`.
static ZERO: [u8; 2 * CHACHA_BLK_SIZE] = [0; 2 * CHACHA_BLK_SIZE];

/// `chacha20_poly1305_tls_cipher` — `e_chacha20_poly1305.c:216-361`, portable (`#else`) arm.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract; `in` readable and `out` writable for `len` bytes.
unsafe fn chacha20_poly1305_tls_cipher(
    ctx: *mut EvpCipherCtx,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    // SAFETY: `ctx` is live per the caller's contract.
    let actx = unsafe { aead_data(ctx) };
    // SAFETY: `actx` is live.
    let plen = unsafe { (*actx).tls_payload_length };
    if len != plen + POLY1305_BLOCK_SIZE {
        return -1;
    }
    // SAFETY: `actx` is live.
    let buf_len: usize;
    // SAFETY: `actx` is live.
    let mut storage = [0u8; 2 * CHACHA_BLK_SIZE + 32];
    let base = storage.as_mut_ptr();
    // SAFETY: the offset aligns `buf` to sixteen bytes within `storage`.
    let buf = unsafe { base.add((0usize.wrapping_sub(base as usize)) & 15) };
    // SAFETY: `buf` is within `storage` and there is room for the block and the Poly1305 block.
    let mut ctr = unsafe { buf.add(CHACHA_BLK_SIZE) };
    // SAFETY: `buf` is within `storage`.
    let mut tohash = unsafe { buf.add(CHACHA_BLK_SIZE - POLY1305_BLOCK_SIZE) };
    let mut tohash_len: usize;
    let mut in_ = in_;
    let mut out = out;
    // SAFETY: `actx`/`ctx` are live; the calls read and write the regions named.
    unsafe {
        if plen <= CHACHA_BLK_SIZE {
            (*actx).key.counter[0] = 0;
            buf_len = 2 * CHACHA_BLK_SIZE;
            ChaCha20_ctr32(
                buf,
                ZERO.as_ptr(),
                buf_len,
                (*actx).key.d.as_ptr(),
                (*actx).key.counter.as_ptr(),
            );
            Poly1305_Init(poly1305_ctx(actx), buf);
            (*actx).key.partial_len = 0;
            ptr::copy_nonoverlapping((*actx).tls_aad.as_ptr(), tohash, POLY1305_BLOCK_SIZE);
            tohash_len = POLY1305_BLOCK_SIZE;
            (*actx).len.aad = EVP_AEAD_TLS1_AAD_LEN as u64;
            (*actx).len.text = plen as u64;

            let mut i = 0usize;
            if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
                while i < plen {
                    *ctr.add(i) ^= *in_.add(i);
                    *out.add(i) = *ctr.add(i);
                    i += 1;
                }
            } else {
                while i < plen {
                    let c = *in_.add(i);
                    *out.add(i) = *ctr.add(i) ^ c;
                    *ctr.add(i) = c;
                    i += 1;
                }
            }
            in_ = in_.add(i);
            out = out.add(i);
            let tail = (0usize.wrapping_sub(i)) & (POLY1305_BLOCK_SIZE - 1);
            ptr::write_bytes(ctr.add(i), 0, tail);
            ctr = ctr.add(i + tail);
            tohash_len += i + tail;
        } else {
            (*actx).key.counter[0] = 0;
            buf_len = CHACHA_BLK_SIZE;
            ChaCha20_ctr32(
                buf,
                ZERO.as_ptr(),
                buf_len,
                (*actx).key.d.as_ptr(),
                (*actx).key.counter.as_ptr(),
            );
            Poly1305_Init(poly1305_ctx(actx), buf);
            (*actx).key.counter[0] = 1;
            (*actx).key.partial_len = 0;
            Poly1305_Update(
                poly1305_ctx(actx),
                (*actx).tls_aad.as_ptr(),
                POLY1305_BLOCK_SIZE,
            );
            tohash = ctr;
            tohash_len = 0;
            (*actx).len.aad = EVP_AEAD_TLS1_AAD_LEN as u64;
            (*actx).len.text = plen as u64;

            if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
                ChaCha20_ctr32(
                    out,
                    in_,
                    plen,
                    (*actx).key.d.as_ptr(),
                    (*actx).key.counter.as_ptr(),
                );
                Poly1305_Update(poly1305_ctx(actx), out, plen);
            } else {
                Poly1305_Update(poly1305_ctx(actx), in_, plen);
                ChaCha20_ctr32(
                    out,
                    in_,
                    plen,
                    (*actx).key.d.as_ptr(),
                    (*actx).key.counter.as_ptr(),
                );
            }
            in_ = in_.add(plen);
            out = out.add(plen);
            let tail = (0usize.wrapping_sub(plen)) & (POLY1305_BLOCK_SIZE - 1);
            Poly1305_Update(poly1305_ctx(actx), ZERO.as_ptr(), tail);
        }

        // `IS_LITTLE_ENDIAN` is the profile: the lengths are copied little-endian in place.
        ptr::copy_nonoverlapping(
            ptr::addr_of!((*actx).len).cast::<u8>(),
            ctr,
            POLY1305_BLOCK_SIZE,
        );
        tohash_len += POLY1305_BLOCK_SIZE;

        Poly1305_Update(poly1305_ctx(actx), tohash, tohash_len);
        OPENSSL_cleanse(buf.cast(), buf_len);
        Poly1305_Final(
            poly1305_ctx(actx),
            if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
                (*actx).tag.as_mut_ptr()
            } else {
                tohash
            },
        );

        (*actx).tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

        if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
            ptr::copy_nonoverlapping((*actx).tag.as_ptr(), out, POLY1305_BLOCK_SIZE);
        } else if CRYPTO_memcmp(tohash.cast(), in_.cast(), POLY1305_BLOCK_SIZE) != 0 {
            ptr::write_bytes(
                out.sub(len - POLY1305_BLOCK_SIZE),
                0,
                len - POLY1305_BLOCK_SIZE,
            );
            return -1;
        }
    }
    len as c_int
}

/// `chacha20_poly1305_cipher` — `e_chacha20_poly1305.c:366-487`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract; `out` writable and `in` readable for `len` bytes, or both
/// NULL for a final call.
unsafe extern "C" fn chacha20_poly1305_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let actx = unsafe { aead_data(ctx) };
    // SAFETY: `actx` is live.
    let mut plen = unsafe { (*actx).tls_payload_length };
    // SAFETY: `actx`/`ctx` are live; the calls read and write the regions named.
    unsafe {
        if (*actx).mac_inited == 0 {
            if plen != NO_TLS_PAYLOAD_LENGTH && !out.is_null() {
                return chacha20_poly1305_tls_cipher(ctx, out, in_, len);
            }
            (*actx).key.counter[0] = 0;
            ChaCha20_ctr32(
                (*actx).key.buf.as_mut_ptr(),
                ZERO.as_ptr(),
                CHACHA_BLK_SIZE,
                (*actx).key.d.as_ptr(),
                (*actx).key.counter.as_ptr(),
            );
            Poly1305_Init(poly1305_ctx(actx), (*actx).key.buf.as_ptr());
            (*actx).key.counter[0] = 1;
            (*actx).key.partial_len = 0;
            (*actx).len.aad = 0;
            (*actx).len.text = 0;
            (*actx).mac_inited = 1;
            if plen != NO_TLS_PAYLOAD_LENGTH {
                Poly1305_Update(
                    poly1305_ctx(actx),
                    (*actx).tls_aad.as_ptr(),
                    EVP_AEAD_TLS1_AAD_LEN as usize,
                );
                (*actx).len.aad = EVP_AEAD_TLS1_AAD_LEN as u64;
                (*actx).aad = 1;
            }
        }

        let mut in_ = in_;
        let mut out = out;
        if !in_.is_null() {
            if out.is_null() {
                // AAD.
                Poly1305_Update(poly1305_ctx(actx), in_, len);
                (*actx).len.aad += len as u64;
                (*actx).aad = 1;
                return len as c_int;
            }
            // Plain- or ciphertext.
            if (*actx).aad != 0 {
                let rem = ((*actx).len.aad % POLY1305_BLOCK_SIZE as u64) as usize;
                if rem != 0 {
                    Poly1305_Update(poly1305_ctx(actx), ZERO.as_ptr(), POLY1305_BLOCK_SIZE - rem);
                }
                (*actx).aad = 0;
            }
            (*actx).tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
            if plen == NO_TLS_PAYLOAD_LENGTH {
                plen = len;
            } else if len != plen + POLY1305_BLOCK_SIZE {
                return -1;
            }
            if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
                chacha_cipher(ctx.cast(), out, in_, plen);
                Poly1305_Update(poly1305_ctx(actx), out, plen);
                in_ = in_.add(plen);
                out = out.add(plen);
                (*actx).len.text += plen as u64;
            } else {
                Poly1305_Update(poly1305_ctx(actx), in_, plen);
                chacha_cipher(ctx.cast(), out, in_, plen);
                in_ = in_.add(plen);
                out = out.add(plen);
                (*actx).len.text += plen as u64;
            }
        }

        if in_.is_null() || plen != len {
            let mut temp = [0u8; POLY1305_BLOCK_SIZE];
            if (*actx).aad != 0 {
                let rem = ((*actx).len.aad % POLY1305_BLOCK_SIZE as u64) as usize;
                if rem != 0 {
                    Poly1305_Update(poly1305_ctx(actx), ZERO.as_ptr(), POLY1305_BLOCK_SIZE - rem);
                }
                (*actx).aad = 0;
            }
            let rem = ((*actx).len.text % POLY1305_BLOCK_SIZE as u64) as usize;
            if rem != 0 {
                Poly1305_Update(poly1305_ctx(actx), ZERO.as_ptr(), POLY1305_BLOCK_SIZE - rem);
            }
            // `IS_LITTLE_ENDIAN` is the profile: the lengths are updated little-endian in place.
            Poly1305_Update(
                poly1305_ctx(actx),
                ptr::addr_of!((*actx).len).cast::<u8>(),
                POLY1305_BLOCK_SIZE,
            );
            Poly1305_Final(
                poly1305_ctx(actx),
                if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
                    (*actx).tag.as_mut_ptr()
                } else {
                    temp.as_mut_ptr()
                },
            );
            (*actx).mac_inited = 0;

            if !in_.is_null() && len != plen {
                // TLS mode.
                if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
                    ptr::copy_nonoverlapping((*actx).tag.as_ptr(), out, POLY1305_BLOCK_SIZE);
                } else if CRYPTO_memcmp(temp.as_ptr().cast(), in_.cast(), POLY1305_BLOCK_SIZE) != 0
                {
                    ptr::write_bytes(out.sub(plen), 0, plen);
                    return -1;
                }
            } else if EVP_CIPHER_CTX_is_encrypting(ctx) == 0
                && CRYPTO_memcmp(
                    temp.as_ptr().cast(),
                    (*actx).tag.as_ptr().cast(),
                    (*actx).tag_len as usize,
                ) != 0
            {
                return -1;
            }
        }
    }
    len as c_int
}

/// `chacha20_poly1305_cleanup` — `e_chacha20_poly1305.c:489-495`.
///
/// # Safety
/// The `EVP_CIPHER::cleanup` contract.
unsafe extern "C" fn chacha20_poly1305_cleanup(ctx: *mut c_void) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let actx = unsafe { aead_data(ctx) };
    if !actx.is_null() {
        // SAFETY: `ctx` is live and the block is `sizeof(*actx) + Poly1305_ctx_size()`.
        unsafe {
            OPENSSL_cleanse(
                (*ctx).cipher_data,
                core::mem::size_of::<EvpChachaAeadCtx>() + Poly1305_ctx_size(),
            )
        };
    }
    1
}

/// `chacha20_poly1305_ctrl` — `e_chacha20_poly1305.c:497-606`.
///
/// # Safety
/// The `EVP_CIPHER::ctrl` contract.
unsafe extern "C" fn chacha20_poly1305_ctrl(
    ctx: *mut c_void,
    type_: c_int,
    arg: c_int,
    ptr_: *mut c_void,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let mut actx = unsafe { aead_data(ctx) };
    match type_ {
        EVP_CTRL_INIT => {
            if actx.is_null() {
                // SAFETY: `ctx` is live; the allocation is zeroed and its size is the struct plus
                // the Poly1305 context that follows it.
                actx = unsafe {
                    let p = CRYPTO_zalloc(
                        core::mem::size_of::<EvpChachaAeadCtx>() + Poly1305_ctx_size(),
                        FILE.as_ptr(),
                        LINE,
                    )
                    .cast::<EvpChachaAeadCtx>();
                    (*ctx).cipher_data = p.cast();
                    p
                };
            }
            if actx.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::E_CHACHA20_POLY1305_508) };
                return 0;
            }
            // SAFETY: `actx` is the context's own block.
            unsafe {
                (*actx).len.aad = 0;
                (*actx).len.text = 0;
                (*actx).aad = 0;
                (*actx).mac_inited = 0;
                (*actx).tag_len = 0;
                (*actx).nonce_len = 12;
                (*actx).tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
                ptr::write_bytes((*actx).tls_aad.as_mut_ptr(), 0, POLY1305_BLOCK_SIZE);
            }
            1
        }
        EVP_CTRL_COPY => {
            if !actx.is_null() {
                let dst = ptr_.cast::<EvpCipherCtx>();
                // SAFETY: `dst` is the caller's live destination context.
                unsafe {
                    (*dst).cipher_data = CRYPTO_memdup(
                        actx.cast(),
                        core::mem::size_of::<EvpChachaAeadCtx>() + Poly1305_ctx_size(),
                        FILE.as_ptr(),
                        LINE,
                    );
                    if (*dst).cipher_data.is_null() {
                        // SAFETY: a compile-time-constant site.
                        raise_site(&err_sites::E_CHACHA20_POLY1305_527);
                        return 0;
                    }
                }
            }
            1
        }
        EVP_CTRL_GET_IVLEN => {
            // SAFETY: `actx` is live and `ptr_` is the caller's `int *`.
            unsafe { *ptr_.cast::<c_int>() = (*actx).nonce_len };
            1
        }
        EVP_CTRL_AEAD_SET_IVLEN => {
            if arg <= 0 || arg > CHACHA20_POLY1305_MAX_IVLEN {
                return 0;
            }
            // SAFETY: `actx` is the context's own block.
            unsafe { (*actx).nonce_len = arg };
            1
        }
        EVP_CTRL_AEAD_SET_IV_FIXED => {
            if arg != 12 {
                return 0;
            }
            // SAFETY: `actx` is live and `ptr_` is readable for twelve bytes.
            unsafe {
                let w0 = u8tou32(core::slice::from_raw_parts(ptr_.cast::<u8>(), 4));
                let w1 = u8tou32(core::slice::from_raw_parts(ptr_.cast::<u8>().add(4), 4));
                let w2 = u8tou32(core::slice::from_raw_parts(ptr_.cast::<u8>().add(8), 4));
                (*actx).nonce[0] = w0;
                (*actx).nonce[1] = w1;
                (*actx).nonce[2] = w2;
                (*actx).key.counter[1] = w0;
                (*actx).key.counter[2] = w1;
                (*actx).key.counter[3] = w2;
            }
            1
        }
        EVP_CTRL_AEAD_SET_TAG => {
            if arg <= 0 || arg > POLY1305_BLOCK_SIZE as c_int {
                return 0;
            }
            if !ptr_.is_null() {
                // SAFETY: `actx` is live and `ptr_` is readable for `arg` bytes.
                unsafe {
                    ptr::copy_nonoverlapping(
                        ptr_.cast::<u8>(),
                        (*actx).tag.as_mut_ptr(),
                        arg as usize,
                    );
                    (*actx).tag_len = arg;
                }
            }
            1
        }
        EVP_CTRL_AEAD_GET_TAG => {
            // SAFETY: `ctx` is live per the contract.
            let encrypting = unsafe { EVP_CIPHER_CTX_is_encrypting(ctx) };
            if arg <= 0 || arg > POLY1305_BLOCK_SIZE as c_int || encrypting == 0 {
                return 0;
            }
            // SAFETY: `actx` is live and `ptr_` is writable for `arg` bytes.
            unsafe {
                ptr::copy_nonoverlapping((*actx).tag.as_ptr(), ptr_.cast::<u8>(), arg as usize)
            };
            1
        }
        EVP_CTRL_AEAD_TLS1_AAD => {
            if arg != EVP_AEAD_TLS1_AAD_LEN {
                return 0;
            }
            let p = ptr_.cast::<u8>();
            // SAFETY: `actx` is live and `p` is readable for `arg` bytes.
            unsafe {
                ptr::copy_nonoverlapping(
                    p,
                    (*actx).tls_aad.as_mut_ptr(),
                    EVP_AEAD_TLS1_AAD_LEN as usize,
                );
                let a = EVP_AEAD_TLS1_AAD_LEN as usize;
                let mut len = ((*p.add(a - 2)) as u32) << 8 | (*p.add(a - 1)) as u32;
                let aad = (*actx).tls_aad.as_mut_ptr();
                if EVP_CIPHER_CTX_is_encrypting(ctx) == 0 {
                    if len < POLY1305_BLOCK_SIZE as u32 {
                        return 0;
                    }
                    len -= POLY1305_BLOCK_SIZE as u32;
                    *aad.add(a - 2) = (len >> 8) as u8;
                    *aad.add(a - 1) = len as u8;
                }
                (*actx).tls_payload_length = len as usize;

                // Merge the record sequence number as per RFC 7905.
                (*actx).key.counter[1] = (*actx).nonce[0];
                (*actx).key.counter[2] =
                    (*actx).nonce[1] ^ u8tou32(core::slice::from_raw_parts(aad, 4));
                (*actx).key.counter[3] =
                    (*actx).nonce[2] ^ u8tou32(core::slice::from_raw_parts(aad.add(4), 4));
                (*actx).mac_inited = 0;
            }
            POLY1305_BLOCK_SIZE as c_int
        }
        EVP_CTRL_AEAD_SET_MAC_KEY => 1,
        _ => -1,
    }
}

/// The translation-unit coordinates, as the allocator reports them.
const FILE: &core::ffi::CStr = c"crypto/evp/e_chacha20_poly1305.c";
const LINE: c_int = 0;

// ---------------------------------------------------------------------------------------------
// The static objects
// ---------------------------------------------------------------------------------------------

/// A `static` `EVP_CIPHER`. The wrapper exists for the reason `src/evp/e_aes.rs`'s own
/// `StaticCipher` does: the inner value is a compile-time constant that nothing writes.
struct StaticCipher(EvpCipher);

// SAFETY: the inner value is fully initialised at compile time and never written; every mutating
// arm of `EVP_CIPHER_up_ref`/`EVP_CIPHER_free` is guarded by `origin`, and `EVP_ORIG_GLOBAL` is
// not `EVP_ORIG_DYNAMIC`.
unsafe impl Sync for StaticCipher {}

/// The common shape of both hand-written initialisers — `e_chacha20_poly1305.c:129-144`,
/// `:608-623` — as a `const fn`.
#[allow(clippy::too_many_arguments)]
const fn legacy_cipher(
    nid: c_int,
    block_size: c_int,
    key_len: c_int,
    iv_len: c_int,
    flags: c_ulong,
    init: Option<CipherLegacyInitFn>,
    do_cipher: Option<CipherLegacyDoFn>,
    cleanup: Option<crate::evp::cipher::CipherLegacyCleanupFn>,
    ctx_size: c_int,
    ctrl: Option<CipherLegacyCtrlFn>,
) -> StaticCipher {
    StaticCipher(EvpCipher {
        nid,
        block_size,
        key_len,
        iv_len,
        flags,
        origin: EVP_ORIG_GLOBAL,
        init,
        do_cipher,
        cleanup,
        ctx_size,
        set_asn1_parameters: None,
        get_asn1_parameters: None,
        ctrl,
        app_data: ptr::null_mut(),
        name_id: 0,
        type_name: ptr::null_mut(),
        description: ptr::null(),
        prov: ptr::null_mut(),
        refcnt: AtomicI32::new(0),
        newctx: None,
        einit: None,
        dinit: None,
        cupdate: None,
        cfinal: None,
        ccipher: None,
        p_einit: None,
        p_dinit: None,
        p_cupdate: None,
        p_cfinal: None,
        freectx: None,
        dupctx: None,
        get_params: None,
        get_ctx_params: None,
        set_ctx_params: None,
        gettable_params: None,
        gettable_ctx_params: None,
        settable_ctx_params: None,
        einit_skey: None,
        dinit_skey: None,
    })
}

/// `chacha20` — `e_chacha20_poly1305.c:129-144`.
static CHACHA20: StaticCipher = legacy_cipher(
    NID_chacha20,
    1,
    CHACHA_KEY_SIZE as c_int,
    CHACHA_CTR_SIZE as c_int,
    EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT,
    Some(chacha_init_key),
    Some(chacha_cipher),
    None,
    core::mem::size_of::<EvpChachaKey>() as c_int,
    None,
);

/// `chacha20_poly1305` — `e_chacha20_poly1305.c:608-623`.
static CHACHA20_POLY1305: StaticCipher = legacy_cipher(
    NID_chacha20_poly1305,
    1,
    CHACHA_KEY_SIZE as c_int,
    12,
    EVP_CIPH_FLAG_AEAD_CIPHER
        | EVP_CIPH_CUSTOM_IV
        | EVP_CIPH_ALWAYS_CALL_INIT
        | EVP_CIPH_CTRL_INIT
        | EVP_CIPH_CUSTOM_COPY
        | EVP_CIPH_FLAG_CUSTOM_CIPHER
        | EVP_CIPH_CUSTOM_IV_LENGTH,
    Some(chacha20_poly1305_init_key),
    Some(chacha20_poly1305_cipher),
    Some(chacha20_poly1305_cleanup),
    0,
    Some(chacha20_poly1305_ctrl),
);

// ---------------------------------------------------------------------------------------------
// The two accessors, in `legacy`-unit order.
// ---------------------------------------------------------------------------------------------

/// `const EVP_CIPHER *EVP_chacha20(void)` — `e_chacha20_poly1305.c:146-149`.
#[no_mangle]
pub extern "C" fn EVP_chacha20() -> *const EvpCipher {
    ptr::addr_of!(CHACHA20.0)
}
/// `const EVP_CIPHER *EVP_chacha20_poly1305(void)` — `e_chacha20_poly1305.c:625-628`.
#[no_mangle]
pub extern "C" fn EVP_chacha20_poly1305() -> *const EvpCipher {
    ptr::addr_of!(CHACHA20_POLY1305.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The accessors answer distinct read-only globals with the authority's sizes.
    #[test]
    fn the_accessors_are_stable_globals_with_the_authority_sizes() {
        fn fields(c: *const EvpCipher) -> (c_int, c_int, c_int, c_int, c_int) {
            // SAFETY: every accessor answers a live static, and the fields are read-only.
            unsafe {
                (
                    (*c).nid,
                    (*c).block_size,
                    (*c).key_len,
                    (*c).iv_len,
                    (*c).origin,
                )
            }
        }
        assert_eq!(fields(EVP_chacha20()), (NID_chacha20, 1, 32, 16, 1));
        assert_eq!(
            fields(EVP_chacha20_poly1305()),
            (NID_chacha20_poly1305, 1, 32, 12, 1)
        );
        assert_ne!(EVP_chacha20(), EVP_chacha20_poly1305());
    }
}
