//! A small, checked DER cursor for the trust-decision path.
//!
//! `der.rs` carries the authority's pointer-walking `asn1_get_length`, which every `d2i_*`
//! template uses. This module is the safe counterpart for code that needs to look at an encoding
//! directly: it never advances past the end of the slice it was given, refuses every length form
//! the authority's reader refuses, bounds indefinite lengths by a scan of the remaining bytes, and
//! bounds nesting by [`MAX_DER_DEPTH`].
//!
//! The contract, in one sentence: **every read either yields a `Tlv` whose `content` slice lies
//! inside the cursor's buffer, or returns `None`.**
//!
//! The module is the reusable reader for the trust-path conversions; it is exercised by this
//! module's tests and is the intended reader for the next cluster (name constraints / policy
//! tree), which is why it is allowed to be unused in the crate's production graph for now.
#![allow(dead_code)]

use core::ffi::c_uchar;

/// Maximum constructed nesting this cursor will descend. The authority's item decoder has its own
/// bound; this one exists so that a crafted encoding cannot drive an unbounded descent here.
pub(crate) const MAX_DER_DEPTH: usize = 32;

/// One tag-length-value element.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Tlv<'a> {
    /// The identifier octet. Only single-octet tags are accepted, which is what the GENERAL_NAME
    /// family uses.
    pub tag: c_uchar,
    /// Bytes of tag + length prefix, i.e. where `content` starts relative to the element.
    pub header: usize,
    /// The element's content, always within the cursor's buffer.
    pub content: &'a [u8],
    /// Whether the length was the `0x80` indefinite form.
    pub indefinite: bool,
}

impl Tlv<'_> {
    /// Whether the constructed bit is set.
    pub(crate) fn constructed(&self) -> bool {
        self.tag & 0x20 != 0
    }
}

/// A cursor over one level of a DER encoding.
#[derive(Clone, Copy)]
pub(crate) struct Der<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Der<'a> {
    /// A cursor over `buf` at depth zero.
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            depth: 0,
        }
    }

    /// The bytes not yet consumed at this level.
    pub(crate) fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Read the next element, advancing past it. `None` at the end of the level, on any malformed
    /// prefix, and on any length that does not fit the remaining bytes.
    pub(crate) fn read(&mut self) -> Option<Tlv<'a>> {
        let rest = &self.buf[self.pos..];
        let tag = *rest.first()?;
        // `0x00` is the end-of-contents octet and never a valid element tag.
        if tag == 0 {
            return None;
        }
        let (len, len_bytes, indefinite) = parse_length(rest.get(1..)?)?;
        let header = 1 + len_bytes;
        if indefinite {
            // Indefinite is only legal for a constructed encoding.
            if tag & 0x20 == 0 {
                return None;
            }
            let body = rest.get(header..)?;
            let end = find_eoc(body, self.depth)?;
            self.pos += header + end + 2;
            Some(Tlv {
                tag,
                header,
                content: &rest[header..header + end],
                indefinite: true,
            })
        } else {
            let end = header.checked_add(len)?;
            if end > rest.len() {
                return None;
            }
            self.pos = self.pos.checked_add(end)?;
            Some(Tlv {
                tag,
                header,
                content: &rest[header..end],
                indefinite: false,
            })
        }
    }

    /// Descend into a constructed element's content, one level deeper.
    pub(crate) fn enter(&self, tlv: &Tlv<'a>) -> Option<Der<'a>> {
        if !tlv.constructed() || self.depth >= MAX_DER_DEPTH {
            return None;
        }
        Some(Der {
            buf: tlv.content,
            pos: 0,
            depth: self.depth + 1,
        })
    }
}

/// Parse a DER length field. Returns `(value, length-octets-used, indefinite)`.
///
/// Refused: a first octet of `0xff`; a long form wider than `usize`; a long form with a leading
/// zero octet; a long form whose value is below `0x80` (the short form was required); and any
/// long form whose bytes are not all present.
fn parse_length(b: &[u8]) -> Option<(usize, usize, bool)> {
    let first = *b.first()?;
    if first < 0x80 {
        return Some((first as usize, 1, false));
    }
    if first == 0x80 {
        return Some((0, 1, true));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > core::mem::size_of::<usize>() {
        return None;
    }
    let bytes = b.get(1..1 + n)?;
    if bytes[0] == 0 {
        return None;
    }
    let mut v = 0usize;
    for &x in bytes {
        v = v.checked_mul(256)?.checked_add(x as usize)?;
    }
    if v < 0x80 {
        return None;
    }
    Some((v, 1 + n, false))
}

/// Find the end-of-contents octet pair closing the indefinite element whose body is `buf`.
///
/// The scan skips complete elements; a nested indefinite element is bounded by a recursive scan
/// whose depth is the same [`MAX_DER_DEPTH`] budget, so the whole search is bounded by both the
/// buffer length and the depth.
fn find_eoc(buf: &[u8], depth: usize) -> Option<usize> {
    if depth >= MAX_DER_DEPTH {
        return None;
    }
    let mut d = Der { buf, pos: 0, depth };
    while d.pos < buf.len() {
        if buf[d.pos] == 0 && buf.get(d.pos + 1) == Some(&0) {
            return Some(d.pos);
        }
        let before = d.pos;
        d.read()?;
        if d.pos == before {
            return None;
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_valid_tlv() {
        let mut d = Der::new(&[0x02, 0x03, 0x01, 0x02, 0x03]);
        let t = d.read().unwrap();
        assert_eq!(t.tag, 0x02);
        assert_eq!(t.content, &[0x01, 0x02, 0x03]);
        assert!(!t.constructed());
        assert_eq!(d.remaining(), &[]);
        assert!(d.read().is_none());
    }

    #[test]
    fn reads_a_long_form_length() {
        let mut buf = alloc_long_form(0x100);
        buf.extend(core::iter::repeat_n(0xAA, 0x100));
        let mut d = Der::new(&buf);
        let t = d.read().unwrap();
        assert_eq!(t.tag, 0x30);
        assert_eq!(t.content.len(), 0x100);
        assert_eq!(t.header, 4);
    }

    #[test]
    fn refuses_a_truncated_length() {
        // Long form claiming four octets with only one present.
        assert!(Der::new(&[0x30, 0x84, 0x01]).read().is_none());
        // A lone tag with no length octet at all.
        assert!(Der::new(&[0x30]).read().is_none());
        // An empty cursor.
        assert!(Der::new(&[]).read().is_none());
    }

    #[test]
    fn refuses_a_length_beyond_the_buffer() {
        let mut d = Der::new(&[0x04, 0x05, 0x01, 0x02]);
        assert!(d.read().is_none());
        assert_eq!(
            d.remaining(),
            &[0x04, 0x05, 0x01, 0x02],
            "no advance on refusal"
        );
    }

    #[test]
    fn reads_an_indefinite_length_with_end_of_contents() {
        let buf = [0x30, 0x80, 0x02, 0x01, 0x2A, 0x00, 0x00];
        let mut d = Der::new(&buf);
        let t = d.read().unwrap();
        assert!(t.indefinite);
        assert_eq!(t.content, &[0x02, 0x01, 0x2A]);
        assert_eq!(d.remaining(), &[]);

        // The content is itself a readable level.
        let mut inner = d;
        let _ = &mut inner;
        let mut level = Der::new(t.content);
        assert_eq!(level.read().unwrap().content, &[0x2A]);
    }

    #[test]
    fn refuses_an_indefinite_length_without_end_of_contents() {
        assert!(Der::new(&[0x30, 0x80, 0x02, 0x01, 0x2A]).read().is_none());
        // A primitive tag may not be indefinite.
        assert!(Der::new(&[0x04, 0x80, 0x00, 0x00]).read().is_none());
    }

    #[test]
    fn refuses_nesting_beyond_the_limit() {
        // `MAX_DER_DEPTH + 1` nested SEQUENCEs, built from the inside out so each length is right.
        let mut buf: Vec<u8> = Vec::new();
        for _ in 0..=MAX_DER_DEPTH {
            let n = buf.len();
            assert!(
                n < 0x80,
                "the test's nesting stays in the short-length form"
            );
            let mut next = vec![0x30, n as u8];
            next.extend_from_slice(&buf);
            buf = next;
        }
        // Walk the nesting: descending `MAX_DER_DEPTH` times must succeed, the next must refuse.
        let mut level = Der::new(&buf);
        for depth in 0..=MAX_DER_DEPTH {
            let t = level
                .read()
                .unwrap_or_else(|| panic!("level {depth} unreadable"));
            match level.enter(&t) {
                Some(inner) => level = inner,
                None => {
                    assert_eq!(depth, MAX_DER_DEPTH, "the limit must be the refusal point");
                    return;
                }
            }
        }
        panic!("nesting beyond MAX_DER_DEPTH was accepted");
    }

    #[test]
    fn refuses_non_minimal_lengths() {
        // 0x81 0x05 should have been 0x05.
        assert!(Der::new(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5])
            .read()
            .is_none());
        // Leading zero in a long form.
        assert!(Der::new(&[0x04, 0x82, 0x00, 0x80]).read().is_none());
        // A long form wider than usize.
        assert!(Der::new(&[0x04, 0x89, 0, 0, 0, 0, 0, 0, 0, 1])
            .read()
            .is_none());
    }

    #[test]
    fn seeded_malformed_inputs_never_panic() {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..20_000 {
            let len = (state as usize) % 24;
            let mut buf = [0u8; 24];
            for b in buf.iter_mut().take(len) {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (state >> 33) as u8;
            }
            let mut d = Der::new(&buf[..len]);
            // Every answer is either a TLV inside the buffer or `None`.
            let mut steps = 0;
            while let Some(t) = d.read() {
                assert!(t.content.len() <= len);
                assert!(t.header + t.content.len() <= len);
                if let Some(mut inner) = d.enter(&t) {
                    while inner.read().is_some() {}
                }
                steps += 1;
                assert!(steps <= len + 1, "the cursor must always advance");
            }
        }
    }

    fn alloc_long_form(n: usize) -> Vec<u8> {
        let mut v = vec![0x30];
        if n < 0x80 {
            v.push(n as u8);
        } else if n <= 0xff {
            v.extend([0x81, n as u8]);
        } else {
            v.extend([0x82, (n >> 8) as u8, (n & 0xff) as u8]);
        }
        v
    }
}
