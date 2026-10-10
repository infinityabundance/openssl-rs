// openssl-rs — the Rust ASan sensitivity canary.
//
// This is NOT product code and is not linked into anything the crate ships. It exists for
// exactly one reason: a "zero findings" result from the crate's ASan run is only trustworthy
// if the instrument that produced it is *known to fire*. This program performs a deliberate
// heap use-after-free through the Rust allocator, with the same `-Zsanitizer=address`
// instrument the 25.10 harness runs use, so the canary proves that instrument — not a
// different sanitizer runtime — diagnoses a real fault in this venue, and that its shadow can
// be mapped. ASan MUST diagnose it with a nonzero exit. If it does not, the harness records
// the canary as *not detected* and refuses to trust any zero-findings result
// (forensics/tools/ms_asan.py).
//
// The read goes through `read_volatile` so the optimiser cannot delete it and make the canary
// silently vacuous.
//
// SPDX-License-Identifier: Apache-2.0

#![allow(unsafe_code)]

fn main() {
    unsafe {
        let layout = std::alloc::Layout::from_size_align(16, 1).unwrap();
        let p = std::alloc::alloc(layout);
        if p.is_null() {
            std::process::exit(2);
        }
        p.write(0x41);
        std::alloc::dealloc(p, layout);
        // Use-after-free read of a freed block.
        let v = std::ptr::read_volatile(p);
        // If ASan did not fire, the canary reached here, which the harness reads as
        // "the instrument did not fire".
        if v == 0x7f {
            eprintln!("canary: NOT-DETECTED");
        }
    }
}
