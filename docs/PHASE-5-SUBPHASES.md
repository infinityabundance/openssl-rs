# Phase 5 — the remaining work, as subphases

Phase 5 is **BN + ASN.1 + DER/PEM**. `BN` is closed: every one of the 201 exports
`bn.h` declares is implemented or handed to a named stratum, and `RT-BN` covers them.
What remains is **3 ASN.1 exports and 27 PEM exports** — the ledger's totals, taken
from `forensics/phase5-obligations.json`, after 5.1 through 5.5 and the first half of
5.6 landed (D76, D77, D85, D86).

`BN` is closed but this document exists because the rest of the stratum is large, and
D73 established that a section is not closed by writing code for it. A subphase closes
only when its exports are implemented **and** a differential court observes them, in the
same commit. Source that no build compiles and no CI checks is invisible to every gate.

## The subphases

| # | Subphase | Owns | Depends on | Court | Exit criterion |
|---|---|---|---|---|---|
| 5.0 | `ABI-PROTOTYPE` | nothing — evidence | — | prototype court, type plane | **COMPLETE** (D74) |
| 5.1 | Leaf primitives + DER codec | the `ASN1_STRING` family, the integer family, the object layer, `ASN1_PCTX`, `ASN1_SCTX`, and `ASN1_get_object`/`put_object`/`object_size`/`tag2bit`/`tag2str`/`parse`/`parse_dump`/`check_infinite_end`/`put_eoc` | Phase 4 (BIO, for the print/parse paths) | `RT-ASN1` | **COMPLETE** (D76) |
| 5.2 | Text conversions | `i2a_*`, `i2t_*` | 5.1 | `RT-ASN1` extension | **COMPLETE** (D76) |
| 5.3 | Codec wrappers | the shared decoder and encoder (`asn1_d2i_ex_primitive`, `asn1_ex_c2i`, `asn1_i2d_ex_primitive`, `asn1_ex_i2c`), the free path, the 26 primitive and multi-string item descriptors, the 36 `d2i_*`/`i2d_*` wrappers of `tasn_typ.c`, `ASN1_BIT_STRING`, `ASN1_NULL`, `d2i_ASN1_UINTEGER`, `a2d_ASN1_OBJECT` | 5.1 | `RT-ASN1` extension | **COMPLETE** (D77) |
| 5.4 | Item machinery | the remaining 14 `*_it` accessors (the two `*_ANY` and the twelve numeric ones), `ASN1_ITEM_lookup`/`get`, `ASN1_item_*`, `ASN1_item_ex_*`, `asn1_d2i_read_bio`, NDEF, `ASN1_item_pack`/`unpack`, `ASN1_dup`, `ASN1_item_print`, `d2i_/i2d_ASN1_SEQUENCE_ANY`/`SET_ANY`, `ASN1_generate_v3`/`nconf`, `ASN1_add_oid_module`/`add_stable_module`, `ASN1_STRING_TABLE_*`, `ASN1_item_i2d_mem_bio` | 5.1, 5.3 | `RT-ASN1-TEMPLATE` | a caller-built template of the authority's shape round-trips, with the templates' `flags`/`tag`/`offset`/`field_name` compared |
| 5.5 | Time | `ASN1_TIME`, `ASN1_UTCTIME`, `ASN1_GENERALIZEDTIME` accessors, and the three `crypto/o_time.c` calendar symbols they stand on | 5.1, 5.4 | `RT-ASN1-TIME` | **COMPLETE** (D85) |
| 5.6 | Strings, masks, printing | `ASN1_STRING_print*`, `set_by_NID`, the string masks, `ASN1_mbstring_*`, `UTF8_getc`/`putc`, `ASN1_str2mask`, `ASN1_PRINTABLE_type`, `ASN1_STRING_to_UTF8`, `ASN1_UNIVERSALSTRING_to_string`, `ASN1_bn_print`, `ASN1_buf_print` | 5.1 | `RT-ASN1-STR` | **COMPLETE** (D86, D87, D88): 18 written, `ASN1_str2mask` with them, and two handed to Phase 6 and Phase 11 |
| 5.7 | `ASN1_TYPE` (ANY) | `ASN1_TYPE_*`, `d2i_/i2d_ASN1_TYPE` | 5.4 | `RT-ASN1-TYPE` | as above |
| 5.8 | NDEF BIO bridge | `BIO_f_asn1`, `BIO_new_NDEF`, `BIO_asn1_get/set_prefix/suffix` (the Phase 4 → 5 hand-offs) | 5.4 | `RT-BIO-ASN1` | **COMPLETE** (D89) for the filter and the bridge; `i2d_ASN1_bio_stream` and `PEM_write_bio_ASN1_stream` are `asn_mime.c`'s and are checked for Phase 12 entanglement before they are written |
| 5.9 | PEM | the 27 `pem.h` exports the stratum still owns, plus the 21 it handed to Phases 7 and 10 | 5.1, 5.4, 5.6 | `RT-PEM` | as above |
| 5.10 | Closure | nothing — evidence | all | — | `open == 0`; seal rewritten from the ledgers; FRF `sensitivity-backed`; Gemel checkpoint |

### Why 5.3 landed before 5.4, when the plan said otherwise

The table above used to say 5.3 depends on 5.4, and D73 used that dependency to justify
landing the leaf types first. Reading `tasn_enc.c` and `tasn_dec.c` whole showed the
dependency was stated the wrong way round: a wrapper is one call to `ASN1_item_d2i` /
`ASN1_item_i2d`, and those two reach the *primitive* arms of the item machinery without
any template being involved. So the wrappers needed the primitive path, which is 5.3's
own work, and waiting for 5.4 would have meant writing that path twice — once here and
once inside 5.4.

The item descriptors that the primitive path needs are the 26 whose `itype` is
`ASN1_ITYPE_PRIMITIVE` or `ASN1_ITYPE_MSTRING` from `tasn_typ.c` and `a_time.c`. They
land in `src/asn1/items.rs` rather than in 5.4 because without them there is nothing for
a wrapper to name. The 14 that remain are the two `*_ANY` templates (which need
`ASN1_TEMPLATE`) and the twelve numeric items (which need `ASN1_PRIMITIVE_FUNCS`), and
defining those without their hooks would produce descriptors that link, get called, and
decode nothing.

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

### Bit strings (`crypto/asn1/a_bitstr.c`, `crypto/asn1/t_bitst.c`)

* `flags & ASN1_STRING_FLAG_BITS_LEFT` says the unused-bit count in `flags & 0x07` is
  authoritative; clearing the flag says "recompute from the trailing zero octets".
  `ASN1_BIT_STRING_set_bit` clears the flag before writing.
* `ossl_i2c_ASN1_BIT_STRING` writes the count byte, then the content, then
  `p[-1] &= (0xff << bits)` — so the masked tail is observable. Its length is
  `1 + len` where `len` is what the **trailing-zero scan left**, not the string's
  `length`; the scan decrements `len`, and every later use reads the decremented value.
* `ossl_c2i_ASN1_BIT_STRING` rejects a content length below 1 or above `INT_MAX`, and a
  count above 7; it masks the final octet with `0xff << i` on the way in, and stores the
  count through `ossl_asn1_string_set_bits_left` — which **always sets** the flag and
  never clears it.
* The declared length is one more than the stored length: the count byte is consumed
  first, so a declared length of exactly 1 produces a **zero-length** string and no
  allocation at all.
* Its `err:` tail raises the *accumulator*, and on the allocation-failure arm that
  accumulator still holds the **unused-bit count** — so a failed decode puts a reason of
  `1..7` in the queue. Defined behaviour and observable, so reproduced.
* `ASN1_BIT_STRING_set_bit` **truncates**: after writing it walks `length` down over
  trailing zero octets, so setting then clearing a bit does not restore the length.
* `ASN1_BIT_STRING_set` does *not* touch `flags`, so a stale count survives it until
  something clears `BITS_LEFT`.
* `ASN1_BIT_STRING_check`'s `flags` names the bits **permitted**: octets past
  `flags_len` permit none (`mask = 0xff`), and a null or empty bit string answers 1.
* `bnam->bitnum` repeats mark an alias pair; `name_print` prints the **first** spelling
  and skips the repeat, while `num_asc`/`set_asc` accept either. The table is terminated
  by a null `lname`, not a count. `name_print` writes its indent and its newline whether
  or not anything matched.

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

`asn1_d2i_ex_primitive` is what every `d2i_ASN1_*` wrapper actually runs. It was once
recorded here as the reason 5.3 depends on 5.4; reading the file whole showed the two
reachable arms of `asn1_item_embed_d2i` — `PRIMITIVE` without templates, and `MSTRING` —
need no template at all, so the path is 5.3's own work and the plan was corrected.

* **`len <= 0` is rejected before any header is read**, with `ASN1_R_TOO_SMALL`, and
  `pval == NULL` with `ERR_R_PASSED_NULL_PARAMETER`. `ASN1_item_d2i` redirects a null
  value slot to a local, so the second is only reachable through `ASN1_item_ex_d2i`.
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
* `MSTRING` is dispatched *before* the decoder: the actual tag is read, the class must be
  `UNIVERSAL` (`MSTRING_NOT_UNIVERSAL`) and `ASN1_tag2bit(tag)` must intersect the item's
  mask (`MSTRING_WRONG_TAG`), and the tag then becomes the decoder's starting `utype`.
  Because `ASN1_tag2bit` is not a bijection, a tag outside the mask is rejected here
  rather than reaching a codec that would have built the wrong type.
* `asn1_ex_c2i`'s per-type length rules live in the **content codec**, not the collector:
  a `BMPSTRING`'s odd length, a `UNIVERSALSTRING`'s non-multiple-of-four, a
  `GENERALIZEDTIME` below 15 and a `UTCTIME` below 13 each raise their own reason.
* A `NULL`'s value is the sentinel `1`, never an allocation; a `BOOLEAN`'s value is
  stored **in the value slot's first four bytes**, not behind it; the string arm's
  allocation-failure path frees the value *unconditionally* and nulls the caller's slot.

### The item layer's ownership contract (`crypto/asn1/tasn_dec.c`, `tasn_fre.c`)

* `asn1_item_ex_d2i_intern` ends with `if (rv <= 0) ASN1_item_ex_free(pval, it);` — so
  **a failed decode frees the caller's value and nulls the caller's slot**. A failed
  `d2i_ASN1_OCTET_STRING(&existing, ...)` destroys `existing`.
* That is also why `asn1_ex_c2i`'s string arm writes `*pval = NULL` after freeing: the
  null is what stops the item layer freeing the same string a second time.
* `ossl_asn1_primitive_free`'s `BOOLEAN` arm writes the item's `size` — its **default** —
  back into the slot and returns without clearing it, so a freed `ASN1_TBOOLEAN` reads as
  `TRUE` and a freed `ASN1_FBOOLEAN` as `FALSE`.
* `ossl_asn1_item_embed_free`'s first guard is asymmetric: a non-primitive item with a
  null value returns immediately, a primitive one does not, because a primitive's value
  may live in the slot.

### The item descriptors (`crypto/asn1/tasn_typ.c`, `crypto/asn1/a_time.c`)

* `IMPLEMENT_ASN1_TYPE(x)` is `IMPLEMENT_ASN1_TYPE_ex(x, x, 0)`, so a plain
  `*_it()`'s `size` field is **`0`**, not `-1`.
* `IMPLEMENT_ASN1_TYPE_ex(ASN1_BOOLEAN, ASN1_BOOLEAN, -1)` — size `-1`, "no default";
  `ASN1_TBOOLEAN` — size `1`; `ASN1_FBOOLEAN` — size `0`. The boolean encoder reads
  that field to decide whether to omit the value, so a wrong `size` changes the bytes.
* `ASN1_OCTET_STRING_NDEF_it`'s `size` carries `ASN1_TFLG_NDEF` (`0x800`) rather than a
  size, which is what `asn1_ex_i2c` tests for.
* `IMPLEMENT_ASN1_MSTRING(x, mask)` gives `itype = MSTRING`, `utype = mask`,
  `size = sizeof(ASN1_STRING)` and `sname` = the item's own symbol name.
* `ASN1_NULL` is `typedef int`, so its `d2i`/`i2d`/`*_new` signatures take `int **` and
  `const int *`, and `ASN1_NULL_new()`'s sentinel is literally address `1`.

### The primitive encode path (`crypto/asn1/tasn_enc.c`)

* `asn1_i2d_ex_primitive` calls the content codec **twice**: once with a null destination
  to size it, once to fill. `len == -1` means **omit the type** and answers 0;
  `len == -2` means **indefinite length**, which becomes `ndef = 2`, a content length of
  0, and a two-byte end-of-contents marker.
* The `usetag` decision is made **after** the sizing call, because the codec is what may
  change `utype` — an `ASN1_TYPE` does exactly that, which is why `SEQUENCE`, `SET` and
  `OTHER` must be tested on the post-call value.
* For `SEQUENCE`, `SET` and `OTHER` no tag is written and the returned length is the
  answer as-is, because the header is part of what the codec returned.
* `i2d_*(val, NULL)` answers the length, `i2d_*(val, &held)` writes and advances,
  `i2d_*(val, &null)` allocates. Only the third allocates, and a non-positive length is
  passed straight through rather than being turned into an allocation of zero bytes.
* An allocation failure answers `-1` **without raising**: a caller distinguishes it from
  "would not fit" by the sign, not by the queue.
* An `OBJECT` with null or empty content is **omitted** (`-1`); a `BOOLEAN` whose value
  equals the item's default is omitted; a null value is omitted for every type except a
  `BOOLEAN` item, whose value is the slot itself.

### The template support layer (`crypto/asn1/tasn_utl.c`, read whole for 5.4)

Every function here is reached by the template interpreter and by nothing else, so it is
recorded before it is written rather than re-derived per call site.

* `ossl_asn1_get_choice_selector`/`_const`/`set_choice_selector` read and write an `int`
  at `it->utype` — for a `CHOICE` item the `utype` field is the **offset of the
  selector**, not a type.
* `ossl_asn1_do_lock`: returns 0 immediately unless the item is a `SEQUENCE` or
  `NDEF_SEQUENCE` *and* its `ASN1_AUX` carries `ASN1_AFLG_REFCOUNT`; `op == 0`
  initialises (reference 1 plus a new lock, and a lock failure raises `ERR_R_CRYPTO_LIB`
  after freeing the reference), `op == 1` increments, `op == -1` decrements and — only at
  zero — frees the lock, nulls the lock field and frees the reference. It answers -1 on
  any failure, so a caller must distinguish -1 from 0.
* `asn1_get_enc_ptr` needs **both** `pval` and `*pval` non-null and `ASN1_AFLG_ENCODING`
  set, and reads the `ASN1_ENCODING` at `aux->enc_offset`. `ossl_asn1_enc_init` sets
  `modified = 1`; `ossl_asn1_enc_free` releases and re-arms the same way.
* `ossl_asn1_enc_save` **frees the previous encoding first**, then treats `inlen <= 0` as
  "no encoding" and answers **0** — so a zero-length save is a failure the caller reports
  as `ASN1_R_AUX_ERROR`.
* `ossl_asn1_enc_restore` answers 0 when the encoding is absent *or* `modified`, and only
  then; a successful restore copies the stored bytes and advances `*out`.
* `ossl_asn1_get_field_ptr` is `*pval + tt->offset` returned as an `ASN1_VALUE **` — and
  for a `BOOLEAN` field that pointer *is* the value, not a pointer to it.
* `ossl_asn1_do_adb` returns `tt` unchanged unless `tt->flags & ASN1_TFLG_ADB_MASK`; it
  reads the selector through `adb->offset` (an `OBJ_obj2nid` for `ADB_OID`, an
  `ASN1_INTEGER_get` for `ADB_INT`), consults `adb->null_tt` when the selector field is
  null, lets `adb_cb` rewrite the selector and treats a 0 answer as
  `ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE`, then does a **linear** search of
  `adb->tbl` and falls back to `default_tt`. A miss with `nullerr` set raises; the
  `NID_undef` value is deliberately *not* special-cased because it can be a legitimate
  table key.

### The `CHOICE` and `SEQUENCE` arms of `asn1_item_embed_d2i` (for 5.4)

* `CHOICE` frees the value the selector currently points at and resets the selector to
  `-1` before re-decoding into an existing value, then tries each template with
  `opt = 1` and takes the first that answers `> 0`; a template answering `-1` means "not
  this alternative", and any other 0-answer frees that partial field and raises
  `ERR_R_NESTED_ASN1_ERROR`. Falling off the end is `ASN1_R_NO_MATCHING_CHOICE_TYPE`
  unless `opt`, in which case the whole item is freed and `-1` returned. The chosen index
  is written back only *after* the loop.
* `SEQUENCE` requires the constructed bit (`ASN1_R_SEQUENCE_NOT_CONSTRUCTED`), honours
  `ASN1_AFLG_BROKEN` by ignoring the declared length, and clears any ADB-derived fields
  **before** the per-field loop. In the loop the last field is decoded with `isopt = 0`
  and every other field with its own `ASN1_TFLG_OPTIONAL`; a `-1` frees and zeroes that
  field and continues; an EOC inside the loop is `ASN1_R_UNEXPECTED_EOC` unless the header
  said indefinite. Afterwards: a missing expected EOC is `ASN1_R_MISSING_EOC`, leftover
  data is `ASN1_R_SEQUENCE_LENGTH_MISMATCH`, and any remaining field that is not OPTIONAL
  is `ASN1_R_FIELD_MISSING`. On success the received bytes are stored with
  `ossl_asn1_enc_save` — which is why a re-encode can return the caller's original bytes
  rather than a re-derivation.
* The `err:` tail adds `"Field="`, the field name, `", Type="` and the item's `sname`
  as **additional error data**, so the queue contents differ between a failure at a named
  field and one at the item itself even when the reason matches.

### The item list (`crypto/asn1/asn1_item_list.c`)

`ASN1_ITEM_lookup` and `ASN1_ITEM_get` scan the authority's *generated*
`asn1_item_list.h`: 147 items, compared by `strcmp` on `sname`, with `get` indexing the
same order. Measured against the ownership atlas, their `_it` accessors are owned by this
stratum for 40 entries, Phase 8 for 7, Phase 10 for 6, Phase 11 for 64 and Phase 12 for
30 — so 107 of the 147 do not exist before Phase 12 and both functions are handed there
with that measurement as the reason (D80).

## Order of work, and why

5.1 first, because everything else is written against `ASN1_STRING` and the primitive
types and there is nothing to build them on otherwise. 5.3 second, because the wrappers
run the primitive path and the primitive path is 5.3's own work — the earlier plan had
this the other way round and was corrected by reading the file (see above). 5.4 next,
because it is what remains of the item machinery: the template interpreter, the two
`*_ANY` items, the numeric items and their `ASN1_PRIMITIVE_FUNCS` hooks. 5.5 and 5.6 can
proceed in parallel with 5.4's later stages — the time *accessors* and the string masks
need the primitive types, not the template interpreter. 5.7 and 5.8 need 5.4. 5.9 needs
5.1, 5.4 and 5.6. `SMIME_*` and the `EVP_PKEY`-shaped readers are not worked here.

Nothing in this list is started before the one it depends on. The staging branch
`phase5-asn1` carries work that compiles and is fmt- and clippy-clean but has not yet
been courted; a section reaches `main` only with the court that observes it, per D73.

### What 5.5 turned out to rest on (D85)

The family is 29 exports and one parser. Two things about it were not in the plan:

* It needs three symbols that are **not** ASN.1 and not Phase 5. `OPENSSL_gmtime`,
  `OPENSSL_gmtime_adj` and `OPENSSL_gmtime_diff` are declared in `crypto.h`, so the
  ownership atlas assigns them to Phase 3; the family is written on top of them, so they
  landed with it, in `src/runtime/time.rs`, phrased as Phase 3's own stratum. The same
  file carries the `struct tm` projection the exported signatures are written against,
  which is a projection of *libc* rather than of OpenSSL and so has no atlas entry — the
  probe measures it instead.
* The three translation units are one module. `a_time.c` is where the parser, the
  constructors and the printers are; `a_utctm.c` and `a_gentm.c` are type guards over
  them. Splitting them into three modules would have produced two modules whose whole
  content is a four-line wrapper, and the ownership rule is keyed on the *declaring
  header*, which is `asn1.h` for all three.

The section closed with `RT-ASN1-TIME` at 1071 observations and one defect found —
`ASN1_TIME_print` skipping the public indirection that collapses the printer's
three-valued answer. That defect is recorded in D85 as the case for measuring entry
points rather than helpers.

### What the first half of 5.6 turned out to rest on (D86)

The 20 exports of this subphase are four unrelated translation units, and the plan had
them as one row because they are all "strings". They are not:

* `a_print.c` and `a_mbstr.c` classify — which of three string types a buffer fits in,
  and which of seven a character fits in. `a_mbstr.c` is the larger of the two by an
  order of magnitude, because it decodes four input encodings to scalar values, narrows
  a mask against them, picks a type and then re-encodes to a possibly different one.
* `a_strnid.c` is policy, not strings: a 28-row compile-time table, a runtime stack that
  shadows it, and a process-global mask whose `STABLE_NO_MASK` exemption exists so that a
  per-NID type a caller pinned is not excluded by a process-wide preference.
* `t_pkey.c` is where `ASN1_bn_print` lives, so a "string" subphase depends on `BN`.
* Two of the row's exports are not implementable here at all: both register a CONF
  module, and `CONF_module_add` is Phase 6. They are handed on, which is why the row's
  own count is 18 rather than 20.

The two defects the court found are both of the least interesting-looking kind, and
both are recorded in D86: a constant recalled rather than read (`ASN1_PRINT_MAX_INDENT`
is 128, not 80) and an early rejection that looks redundant next to the parse that
follows it. The third finding was not in this stratum at all — it was a Phase-3 refusal
of `OPENSSL_INIT_LOAD_CONFIG` that this stratum's first caller turned into an
observable difference.

SPDX-License-Identifier: Apache-2.0
