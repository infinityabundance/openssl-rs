//! `crypto/bsearch.c` — the authority's own binary search.
//!
//! OpenSSL does not use libc's `bsearch`. It has its own, because it needs an
//! element size in bytes rather than a type, a **flags** argument that decides what
//! to answer on a miss and which of several equal matches to return, and — the part
//! that makes it observable — a comparator that is called with the *key pointer*
//! followed by the element's *address*, so a comparator may compare by address.
//!
//! ```c
//! const void *ossl_bsearch(const void *key, const void *base, int num,
//!     int size, int (*cmp)(const void *, const void *), int flags)
//! ```
//!
//! ## What the two flags mean
//!
//! | flag | effect |
//! |---|---|
//! | `OSSL_BSEARCH_VALUE_ON_NOMATCH` | on a miss, return the last probed position instead of NULL |
//! | `OSSL_BSEARCH_FIRST_VALUE_ON_MATCH` | on a hit, walk **backwards** to the first of several equal elements |
//!
//! With neither flag and a miss the answer is NULL; with neither flag and a hit the
//! answer is whichever of the equal elements the halving happened to land on, which
//! is *not* necessarily the first. A caller that needs the first must ask for it.
//!
//! ## The Rust shape, and why it is an index protocol
//!
//! The C interface takes a byte array and an element size, and calls a function
//! pointer. Those three things exist to serve C's lack of generics. What the
//! algorithm *does* is a sequence of probes over `0..num`, so the mirror here takes
//! the count and a probe that answers the comparison for one index. The loop below
//! is the C loop, including the two details that decide an answer: the probe is
//! `l + (h - l) / 2` rather than `(l + h) / 2`, and `c` survives the loop so the
//! post-loop branch tests the **last** comparison rather than a fresh one.
//!
//! ## Why this file exists rather than a third private transcription
//!
//! The algorithm was already reproduced twice, inside the two callers that needed it
//! first: `src/runtime/stack.rs` reduces it to a stack's element type, and
//! `src/runtime/obj.rs` reduces it to an index list with a closure comparator. Both
//! were written as local helpers because a second caller had not arrived. A third
//! caller — the property engine's `property_query.c` — is what makes the duplication
//! worth removing, and this file is the mirror of `crypto/bsearch.c` itself, which is
//! where the algorithm belongs.
//!
//! **The two specialised transcriptions are deliberately left in place for now.**
//! Both are verified by courts (`RT-STACK`, `RT-OBJ-STREAM`) against the authority,
//! so rewriting them onto this helper would change verified code to save lines rather
//! than to fix anything, and the seals of Phases 3 and 5 did not name it as an
//! obligation. Consolidating them is a named follow-up in
//! `docs/PHASE-6-SUBPHASES.md`, not a silent rewrite.

use core::ffi::c_int;

/// `OSSL_BSEARCH_VALUE_ON_NOMATCH` — `include/internal/numbers.h`.
#[allow(dead_code)]
// unreachable until 6.7b's grammar calls it, which is the stratum that needs it
pub(crate) const OSSL_BSEARCH_VALUE_ON_NOMATCH: c_int = 0x01;
/// `OSSL_BSEARCH_FIRST_VALUE_ON_MATCH` — `include/internal/numbers.h`.
#[allow(dead_code)]
// unreachable until 6.7b's grammar calls it, which is the stratum that needs it
pub(crate) const OSSL_BSEARCH_FIRST_VALUE_ON_MATCH: c_int = 0x02;

/// The comparison protocol: given an index, answer negative when the key sorts
/// before that element, positive when after, zero when equal.
#[allow(dead_code)]
// unreachable until 6.7b's grammar calls it, which is the stratum that needs it
pub(crate) type Probe<'a> = &'a mut dyn FnMut(usize) -> c_int;

/// `ossl_bsearch`, over an index space rather than a byte array.
///
/// Returns the index of the element the authority's algorithm would return, or
/// `None` when it would answer NULL.
#[allow(dead_code)]
// unreachable until 6.7b's grammar calls it, which is the stratum that needs it
pub(crate) fn ossl_bsearch(len: usize, flags: c_int, cmp: Probe<'_>) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let mut l: usize = 0;
    let mut h: usize = len;
    let mut i: usize = 0;
    let mut c: c_int = 0;
    while l < h {
        i = l + (h - l) / 2;
        c = cmp(i);
        if c < 0 {
            h = i;
        } else if c > 0 {
            l = i + 1;
        } else {
            break;
        }
    }
    if c != 0 && (flags & OSSL_BSEARCH_VALUE_ON_NOMATCH) == 0 {
        return None;
    }
    if c == 0 && (flags & OSSL_BSEARCH_FIRST_VALUE_ON_MATCH) != 0 {
        while i > 0 && cmp(i - 1) == 0 {
            i -= 1;
        }
    }
    Some(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_array_has_no_answer() {
        assert_eq!(ossl_bsearch(0, 0, &mut |_| 0), None);
    }

    #[test]
    fn a_miss_answers_none_unless_the_flag_asks_for_the_probe() {
        let values = [1i32, 3, 5, 7, 9];
        let key = 4i32;
        assert_eq!(
            ossl_bsearch(values.len(), 0, &mut |i| key - values[i]),
            None
        );
        // With the flag, the last probed position comes back instead.
        let probed = ossl_bsearch(values.len(), OSSL_BSEARCH_VALUE_ON_NOMATCH, &mut |i| {
            key - values[i]
        });
        assert!(probed.is_some());
    }

    #[test]
    fn a_hit_without_the_first_flag_may_not_be_the_first_equal_element() {
        let values = [2i32, 2, 2, 2, 2];
        let key = 2i32;
        let plain = ossl_bsearch(values.len(), 0, &mut |i| key - values[i]);
        assert!(plain.is_some());
        let first = ossl_bsearch(values.len(), OSSL_BSEARCH_FIRST_VALUE_ON_MATCH, &mut |i| {
            key - values[i]
        });
        assert_eq!(first, Some(0), "the backwards walk reaches the first");
    }

    #[test]
    fn every_distinct_element_is_found() {
        let values = [10i32, 20, 30, 40, 50, 60, 70];
        for (want, v) in values.iter().enumerate() {
            let key = *v;
            let got = ossl_bsearch(values.len(), 0, &mut |i| key - values[i]);
            assert_eq!(got, Some(want), "value {v}");
        }
    }
}
