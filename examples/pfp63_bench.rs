//! PFP-63 fallback-throughput harness.
//!
//! Calls the exported block entry points through the same dispatch a consumer sees.
//! With the default CPU it measures the AES-NI arm; with `OPENSSL_ia32cap` clearing
//! the AES bit (bit 25 of the first vector, e.g. `OPENSSL_ia32cap=~0x2000000`) it
//! measures the portable constant-pattern fallback. Build and run in the court:
//!
//! ```text
//! cargo build --release --example pfp63_bench
//! PFP63_ITERS=20000000 ./target/release/examples/pfp63_bench
//! OPENSSL_ia32cap=~0x2000000 PFP63_ITERS=200000 ./target/release/examples/pfp63_bench
//! ```

use std::hint::black_box;
use std::time::Instant;

use openssl_rs::aes::{AES_decrypt, AES_encrypt, AES_set_decrypt_key, AES_set_encrypt_key, AesKey};
use openssl_rs::modes::gcm::{
    CRYPTO_gcm128_encrypt, CRYPTO_gcm128_new, CRYPTO_gcm128_release, CRYPTO_gcm128_setiv,
    CRYPTO_gcm128_tag,
};
use openssl_rs::modes::Block128F;

/// Forces the portable GHASH carrier into the linked artefact so its emitted code can
/// be audited; the call is one block and runs before any timing.
fn gcm_touch() {
    unsafe extern "C" fn block(input: *const u8, out: *mut u8, key: *const core::ffi::c_void) {
        // SAFETY: the GCM context passes the schedule it was given.
        unsafe { AES_encrypt(input, out, key.cast::<AesKey>()) }
    }

    let key = [0x2bu8; 16];
    let mut ek = AesKey {
        rd_key: [0; 60],
        rounds: 0,
    };
    // SAFETY: live locals and the exported contracts.
    unsafe {
        assert_eq!(AES_set_encrypt_key(key.as_ptr(), 128, &mut ek), 0);
        let f: Block128F = block;
        let ctx = CRYPTO_gcm128_new((&mut ek as *mut AesKey).cast(), f);
        if !ctx.is_null() {
            let iv = [0u8; 12];
            let input = [0u8; 16];
            let mut out = [0u8; 16];
            let mut tag = [0u8; 16];
            CRYPTO_gcm128_setiv(ctx, iv.as_ptr(), iv.len());
            CRYPTO_gcm128_encrypt(ctx, input.as_ptr(), out.as_mut_ptr(), input.len());
            CRYPTO_gcm128_tag(ctx, tag.as_mut_ptr(), tag.len());
            CRYPTO_gcm128_release(ctx);
            black_box(out);
            black_box(tag);
        }
    }
}

fn main() {
    gcm_touch();
    let iters: usize = std::env::var("PFP63_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000_000);

    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = i as u8;
    }
    let mut block = [0u8; 16];
    for (i, b) in block.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(17);
    }

    let forced = std::env::var("OPENSSL_ia32cap")
        .map(|v| v.contains('~'))
        .unwrap_or(false);
    println!(
        "dispatch: {} (iters={iters})",
        if forced {
            "portable (forced)"
        } else {
            "hardware if present"
        }
    );

    for bits in [128i32, 192, 256] {
        let mut ek = AesKey {
            rd_key: [0; 60],
            rounds: 0,
        };
        let mut dk = AesKey {
            rd_key: [0; 60],
            rounds: 0,
        };
        // SAFETY: the locals are live for the whole loop; the schedules are the
        // exported ABI's own type.
        unsafe {
            assert_eq!(AES_set_encrypt_key(key.as_ptr(), bits, &mut ek), 0);
            assert_eq!(AES_set_decrypt_key(key.as_ptr(), bits, &mut dk), 0);
        }
        let mut out = [0u8; 16];

        // Warm the dispatch `OnceLock`.
        // SAFETY: as above.
        unsafe {
            AES_encrypt(black_box(block.as_ptr()), out.as_mut_ptr(), &ek);
        }

        let t = Instant::now();
        for _ in 0..iters {
            // SAFETY: live locals with the exported block contract.
            unsafe {
                AES_encrypt(black_box(block.as_ptr()), out.as_mut_ptr(), &ek);
            }
        }
        let secs = t.elapsed().as_secs_f64();
        let enc = iters as f64 * 16.0 / secs / (1024.0 * 1024.0);
        black_box(out);

        let t = Instant::now();
        for _ in 0..iters {
            // SAFETY: live locals with the exported block contract.
            unsafe {
                AES_decrypt(black_box(block.as_ptr()), out.as_mut_ptr(), &dk);
            }
        }
        let secs = t.elapsed().as_secs_f64();
        let dec = iters as f64 * 16.0 / secs / (1024.0 * 1024.0);
        black_box(out);

        println!("AES-{bits}: encrypt {enc:.1} MB/s, decrypt {dec:.1} MB/s");
    }
}
