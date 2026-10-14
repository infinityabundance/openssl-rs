// openssl-rs — the Rust TSan sensitivity canary.
//
// This is NOT product code and is not linked into anything the crate ships. It exists for
// exactly one reason: a "no data race" result from the crate's ThreadSanitizer run is only
// trustworthy if the instrument that produced it is *known to fire*. This program performs a
// deliberate data race — one thread writes a shared heap location while another reads it,
// unsynchronised — with the same `-Zsanitizer=thread` instrument the 25.11 harness runs use, so
// the canary proves that instrument — not a different sanitizer runtime — diagnoses a real race
// in this venue, and that the TSan runtime starts under the venue's process limits. TSan MUST
// diagnose it with a nonzero exit and a `data race` report. If it does not, the harness records
// the canary as *not detected* and refuses to trust any no-race result
// (forensics/tools/ms_tsan.py).
//
// The accesses go through `read_volatile`/`write_volatile` so the optimiser cannot delete the
// loops and make the canary silently vacuous; a volatile access is still a plain data race that
// ThreadSanitizer instruments. The race is carried across the thread boundary by an address
// (`usize` is `Send`), not by a raw pointer, so the canary compiles without an `unsafe impl Send`.
//
// SPDX-License-Identifier: Apache-2.0

#![allow(unsafe_code)]

use std::thread;

fn main() {
    let cell = Box::new(0u32);
    let raw: *mut u32 = Box::into_raw(cell);
    let addr = raw as usize;

    let writer = thread::spawn(move || {
        let p = addr as *mut u32;
        for i in 0..4_000_000u32 {
            unsafe {
                std::ptr::write_volatile(p, i);
            }
        }
    });
    let reader = thread::spawn(move || {
        let p = addr as *mut u32;
        let mut acc = 0u32;
        for _ in 0..4_000_000u32 {
            acc = acc.wrapping_add(unsafe { std::ptr::read_volatile(p) });
        }
        acc
    });

    writer.join().unwrap();
    let _ = reader.join().unwrap();
    unsafe {
        drop(Box::from_raw(raw));
    }
    // If TSan did not fire, the canary reached here, which the harness reads as
    // "the instrument did not fire".
    eprintln!("canary: NOT-DETECTED");
}
