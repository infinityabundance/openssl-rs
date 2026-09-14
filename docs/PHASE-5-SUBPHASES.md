# Phase 5 — the remaining work, as subphases

Phase 5 is **BN + ASN.1 + DER/PEM**. `BN` is closed: every one of the 201 exports
`bn.h` declares is implemented or handed to a named stratum, and `RT-BN` covers them.
What remains is **314 ASN.1 exports and 48 PEM exports** — the ledger's totals, taken
from `forensics/phase5-obligations.json`.

`BN` is closed but this document exists because the rest of the stratum is large, and
D73 established that a section is not closed by writing code for it. A subphase closes
only when its exports are implemented **and** a differential court observes them, in the
same commit. Source that no build compiles and no CI checks is invisible to every gate.

## The subphases

| # | Subphase | Owns | Depends on | Court | Exit criterion |
|---|---|---|---|---|---|
| 5.0 | `ABI-PROTOTYPE` | nothing — evidence | — | prototype court, type plane | **COMPLETE** (D74) |
| 5.1 | Leaf primitives + DER codec | the `ASN1_STRING` family, the integer family, bit string, object, `NULL`, `ASN1_PCTX`, `ASN1_SCTX`, and `ASN1_get_object`/`put_object`/`object_size`/`tag2bit`/`tag2str`/`parse`/`parse_dump`/`check_infinite_end`/`put_eoc` | Phase 4 (BIO, for the print/parse paths) | `RT-ASN1` | every export implemented or handed on; `RT-ASN1` 0 residuals |
| 5.2 | Text conversions | `i2a_*`, `i2t_*`, `a2i_*`, `a2d_ASN1_OBJECT` | 5.1 | `RT-ASN1` extension | as above |
| 5.3 | Codec wrappers | the 22 `d2i_*`/`i2d_*` primitive wrappers over 5.1's types, `d2i_ASN1_UINTEGER` | 5.4 (templates) | `RT-ASN1` extension | as above |
| 5.4 | Item machinery | the 42 `*_it` accessors, `ASN1_ITEM_lookup`/`get`, `ASN1_item_*`, `ASN1_item_ex_*`, `asn1_d2i_read_bio`, NDEF, `ASN1_item_pack`/`unpack`, `ASN1_dup`, `ASN1_item_print`, `ASN1_generate_v3`/`nconf` | 5.1 | `RT-ASN1-TEMPLATE` | a caller-built template of the authority's shape round-trips, with the templates' `flags`/`tag`/`offset`/`field_name` compared |
| 5.5 | Time | `ASN1_TIME`, `ASN1_UTCTIME`, `ASN1_GENERALIZEDTIME` | 5.1, 5.4 | `RT-ASN1-TIME` | as above |
| 5.6 | Strings, masks, printing | `ASN1_STRING_print*`, `set_by_NID`, the string table, `ASN1_mbstring_*`, `UTF8_getc`/`putc`, `ASN1_str2mask`, `ASN1_PRINTABLE_type` | 5.1 | `RT-ASN1-STR` | as above |
| 5.7 | `ASN1_TYPE` (ANY) | `ASN1_TYPE_*`, `d2i_/i2d_ASN1_TYPE`, `d2i_/i2d_ASN1_SEQUENCE_ANY`, `d2i_/i2d_ASN1_SET_ANY` | 5.4 | `RT-ASN1-TYPE` | as above |
| 5.8 | NDEF BIO bridge | `BIO_f_asn1`, `BIO_new_NDEF`, `BIO_asn1_get/set_prefix/suffix` (the Phase 4 → 5 hand-offs) | 5.4 | `RT-BIO-ASN1` | as above |
| 5.9 | PEM | the 48 `pem.h` exports: `PEM_read*`/`PEM_write*`, `PEM_bytes_read_bio`, `PEM_do_header`, `PEM_def_callback`, `PEM_dek_info`, `PEM_proc_type`, the `b2i_*`/`i2b_*` pair-code readers and writers, `PEM_X509_INFO_read*`, `PEM_Sign*` | 5.1, 5.4, 5.6 | `RT-PEM` | as above |
| 5.10 | Closure | nothing — evidence | all | — | `open == 0`; seal rewritten from the ledgers; FRF `sensitivity-backed`; Gemel checkpoint |

### The hand-offs, which leave the stratum by disposition and not by implementation

These are in the Phase 5 ledger because `asn1.h` and `pem.h` declare them, which is the
rule the ownership atlas applies. Their *behaviour* belongs to a later stratum, so each
is recorded as deferred, with its target, and the ledger's arithmetic keeps them:

* `SMIME_crlf_copy`, `SMIME_read_ASN1`, `SMIME_read_ASN1_ex`, `SMIME_text`,
  `SMIME_write_ASN1`, `SMIME_write_ASN1_ex` → **Phase 12** (`asm_mime.c` is CMS/PKCS#7).
* `ASN1_item_sign_ex`, `ASN1_item_verify_ex` → **Phase 7** (`EVP_PKEY`/`EVP_MD`).
* `b2i_PVK_bio`, `b2i_PVK_bio_ex`, `b2i_PrivateKey`, `b2i_PrivateKey_bio`,
  `b2i_PublicKey`, `b2i_PublicKey_bio`, `i2b_PVK_bio`, `i2b_PVK_bio_ex`,
  `i2b_PrivateKey_bio`, `i2b_PublicKey_bio`, the typed `PEM_read_bio_PrivateKey` family,
  `d2i_PKCS8PrivateKey`/`i2d_PKCS8PrivateKey` → **Phase 7 and Phase 10**.

## What each subphase must honour — authority facts already established

Recorded here so they are not re-derived per subphase. Every one was read from the
authority's own source at `/work/forensics/authorities/src/openssl-3.6.4`, and every one
is a behaviour a probe can compare.

### Integers and enumerated (`crypto/asn1/a_int.c`)

* `ASN1_INTEGER` stores a **magnitude**; the sign lives in `type & V_ASN1_NEG`. The DER
  encoding is computed separately by `i2c_ibuf`/`c2i_ibuf`.
* `i2c_ibuf` pads `00` for a positive whose top bit is set; for a negative it pads `FF`
  when the magnitude's first octet is `> 0x80`, and when that octet is exactly `0x80`
  it pads **only if a later octet is non-zero** (so `-0x8000…00` gains no `FF` but
  `-0x8000…01` does). Zero content encodes as one `00` octet.
* `c2i_ibuf` rejects content whose first two octets have matching sign bits
  (`ILLEGAL_PADDING`), with a distinct `ILLEGAL_ZERO_CONTENT` for empty content.
* `asn1_string_get_int64` rejects a value whose `type & ~V_ASN1_NEG` is not the
  expected type, with `WRONG_INTEGER_TYPE`; `asn1_string_get_uint64` additionally
  rejects a negative with `ILLEGAL_NEGATIVE_VALUE`.
* `asn1_string_set_int64` sets `type = itype` and then **clears** or sets `V_ASN1_NEG`
  by the sign; it goes through `ASN1_STRING_set`, so the buffer is `len + 1` and
  NUL-terminated.
* `ASN1_INTEGER_get(NULL)` answers **0**; a wrong type or an out-of-`long` value
  answers `-1`. `ASN1_ENUMERATED_get(NULL)` answers **0**; a wrong type answers `-1`;
  content longer than a `long` answers **`0xffffffffL`**, not `-1`.
* `bn_to_asn1_string` sets `ret->type |= V_ASN1_NEG_INTEGER` regardless of `atype`.
  This is not a bug: `V_ASN1_ENUMERATED | V_ASN1_NEG_INTEGER == V_ASN1_NEG_ENUMERATED`.
  It allocates `max(BN_num_bytes, 1)` and writes a literal `0` for zero.
* `d2i_ASN1_UINTEGER` is the "broken software" reader: it ignores the sign bit and
  strips one leading `00` when the content is longer than one octet.

### Bit strings (`crypto/asn1/a_bitstr.c`)

* `flags & ASN1_STRING_FLAG_BITS_LEFT` says the unused-bit count in `flags & 0x07` is
  authoritative; clearing the flag says "recompute from the trailing zero octets".
  `ASN1_BIT_STRING_set_bit` clears the flag before writing.
* `ossl_i2c_ASN1_BIT_STRING` writes the count byte, then the content, then
  `p[-1] &= (0xff << bits)` — so the masked tail is observable.
* `ossl_c2i_ASN1_BIT_STRING` rejects a content length below 1 or above `INT_MAX`, and a
  count above 7; it masks the final octet with `0xff << i` on the way in, and stores the
  count through `ossl_asn1_string_set_bits_left`.

### Objects (`crypto/asn1/a_object.c`)

* `ossl_c2i_ASN1_OBJECT` rejects `len <= 0`, `len > INT_MAX`, and a last octet whose top
  bit is set; it then asks `OBJ_obj2nid` on a **temporary non-owning object** and, on a
  match, returns the shared static table entry — no allocation — freeing the caller's
  `*a` first. Only an unregistered OID becomes dynamic.
* For the dynamic path it applies the X.690 8.19.2 sub-identifier check: a `0x80` octet
  may not lead a sub-identifier unless the previous octet also continued.
* `ASN1_OBJECT_new` is `zalloc` with `flags = ASN1_OBJECT_FLAG_DYNAMIC`;
  `ASN1_OBJECT_create` builds a **stack** object flagged dynamic and hands it to
  `OBJ_dup`, so the caller keeps ownership of every argument; `ASN1_OBJECT_free` frees
  only what the `DYNAMIC*` bits say and does not clear them.
* `i2a_ASN1_OBJECT` writes exactly **four** bytes (`"NULL"`) for a null-`data` object,
  and `"<INVALID>"` followed by `BIO_dump` of the raw content for an OID whose text is
  empty. `i2t_ASN1_OBJECT` is `OBJ_obj2txt(..., no_name = 0)`.

### The primitive decode path (`crypto/asn1/tasn_dec.c`)

`asn1_d2i_ex_primitive` is what every `d2i_ASN1_*` wrapper actually runs, and its
branches are observable. It is the reason 5.3 depends on 5.4 rather than the reverse:
a wrapper implemented directly, without the path, would have to reproduce all of this by
hand and would drift.

* A `SEQUENCE`, `SET` or `OTHER` is kept **in encoded form**, and `SEQUENCE`/`SET` must
  be constructed (`TYPE_NOT_CONSTRUCTED` otherwise).
* A constructed string is **collected** with `asn1_collect` into a `BUF_MEM`, with a
  final NUL appended; the internal tags are deliberately not checked, only the
  `UNIVERSAL` class.
* An indefinite length is resolved by `asn1_find_end`.
* `NULL`, `BOOLEAN`, `OBJECT`, `INTEGER` and `ENUMERATED` in constructed form are
  `TYPE_NOT_PRIMITIVE`.
* A tag/class mismatch is reported as `NESTED_ASN1_ERROR` from the caller, not as the
  tag error itself.
* Optional and absent fields return `-1` from the tag check, not `0`.

## Order of work, and why

5.1 first, because everything else is written against `ASN1_STRING` and the primitive
types and there is nothing to build them on otherwise. 5.4 before 5.3 even though the
wrapper *names* are more familiar, because the wrappers are a thin layer over the
template path and implementing them directly would mean writing that path twice. 5.5 and
5.6 can proceed in parallel with 5.4's later stages — they need the primitive types, not
the template interpreter, except for the `_it` accessors. 5.7 and 5.8 need 5.4. 5.9 needs
5.1, 5.4 and 5.6. `SMIME_*` and the `EVP_PKEY`-shaped readers are not worked here.

Nothing in this list is started before the one it depends on. `src/asn1/{layout,string,der}.rs`
exist in the working tree and are **not committed**: they are 2,632 lines that no build
compiles, and the commit that lands them is the one that adds `pub mod asn1;` *and* the
court that observes them, per D73.

SPDX-License-Identifier: Apache-2.0
