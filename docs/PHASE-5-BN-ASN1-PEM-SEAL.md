# Phase 5 — `BIGNUM`, ASN.1 and PEM: seal

**STATUS: complete (docs/DECISIONS.md D99).** Every export this stratum owns is either implemented and observed by a differential court, or handed to a named later stratum with the dependency it is waiting on: `open_in_this_stratum` in `forensics/phase5-obligations.json` is zero. At the seal it derived `in-progress`, and not because of anything it did: `forensics/tools/phase_state.py` enforces that a phase may be complete only if every earlier phase is, and D97 had reopened Phases 3 and 4. D99 re-closed them, which is the rule doing what it was written for.

**For every count in this document, read `docs/SEAL-CENSUS.md`**, which is generated from the ledgers and the court results by `forensics/tools/render_seal_census.py`.

This is **not** a claim that openssl-rs is a usable OpenSSL. `docs/SEAL-CENSUS.md` carries the current figures: 1841 of 5,896 `libcrypto` exports are implemented, and all 603 `libssl` exports remain `SCAFFOLDED` and abort when called.

- Authority: `openssl-3.6.4-production` (with `openssl-3.6.3-historical` admitted for
  the oracle-versus-oracle trajectory in `docs/SECURITY_DIVERGENCE_POLICY.md`)
- Court results: `artifacts/phase5/COURTS.json` — 9 courts, 9,669 observations, 0
  residuals, `all_pass` true
- Obligation ledger: `forensics/phase5-obligations.json` — 565 exports owned,
  **474 implemented**, 91 handed on, **0 open in this stratum**. The figures are in
  `docs/SEAL-CENSUS.md`; D97 removed one disputed row from the hand-off list
  (`BIO_f_asn1` and `BIO_new_NDEF` are declared in `asn1.h` and were always this
  stratum's outright, so listing them as a discharged hand-off was a prefix artifact)
- Derived state: `forensics/phase-state.json`

## 1. What this phase owns, and how that was decided

Phase 5's scope is derived by `forensics/tools/phase5_obligations.py` from the Phase 1
atlas under one stated rule: **a symbol belongs to the stratum that owns the header
that declares it**. `d2i_X509` and `d2i_ASN1_INTEGER` look alike and belong to
different strata, and the name cannot separate them; the declaring header can.
`pem.h` is the one header whose exports are not a module, so the tool resolves those
by the type in the symbol's name.

The rule has now been applied in both directions, and both directions have caught a
real loss. D49 and D51 record the first: `a2d_ASN1_OBJECT` and the eleven `crypto/o_str.c`
exports matched no stratum's prefixes, so they were invisible to every obligation
table at once. D92 records the second, which is the same error one level further out:
`SMIME_crlf_copy` and `i2d_ASN1_bio_stream` were handed to Phase 12 on the reason
"operates over CMS and PKCS#7; asn_mime.c" — a statement about a *file*. The
declaring-header rule always gave them to this stratum, and their only dependencies
(`BIO_f_buffer`, `strip_eol`) were present. A hand-off whose reason is a file name
cannot be checked; one whose reason is a subsystem can.

| module | owned | implemented | handed on |
|---|---|---|---|
| `src/asn1/` | 393 | 302 | 91 |
| `src/bn/` | 170 | 170 | 0 |
| `src/pem/` | 2 | 2 | 0 |
| **total** | **565** | **474** | **91** |

The 91 hand-offs name the subsystem each is waiting on rather than the file it lives
in: 1 to Phase 6 (`OSSL_LIB_CTX`), 26 to Phase 7 (the EVP codec — `EVP_ENCODE_CTX`,
`EVP_CIPHER`, `EVP_MD_CTX`, `EVP_PKEY`, `BIO_f_base64`), 31 to Phase 9 (`RAND`),
16 to Phase 10 (PKCS#8 and the `b2i_*`/`i2b_*` readers), 10 to Phase 11 (`X509_REQ`,
`X509_INFO`, the `X509_ALGOR` set), 7 to Phase 12 (`asn_mime.c`'s MIME reader and
writer, and the `asn1_item_list.h` enumeration). `ownership_audit.py` reconciles each
edge against the deferring stratum, so nothing is counted twice and nothing falls
between two strata.

## 2. What has been built

| module | what it is |
|---|---|
| `bn/limbs` | pure limb arithmetic — add, subtract, compare, multiply, shift, divide, remainder, GCD, modular inverse — with no FFI and no OpenSSL types. |
| `bn/bignum` | the opaque `BIGNUM`: lifetime, predicates, flags, the constant-time surface, and every byte and string conversion. |
| `bn/arith`, `mont`, `recp`, `nist`, `kron`, `blinding`, `gf2m`, `ctx` | the `BN_*` entry points: arithmetic, Montgomery, reciprocal division, the NIST reductions, Kronecker, blinding, `GF(2)[x]`, `BN_CTX` and `BN_GENCB`. |
| `asn1/der` | the DER header codec: `ASN1_get_object`, `ASN1_put_object`, `ASN1_object_size`, `ASN1_tag2bit`, `ASN1_tag2str` and the two parsers. |
| `asn1/string`, `prim`, `bitstr`, `typ`, `items` | `ASN1_STRING` and its fifteen types, the `ASN1_INTEGER`/`ASN1_ENUMERATED` family with its two's-complement codec, `ASN1_BIT_STRING`, `ASN1_OBJECT`, `ASN1_NULL`, `ASN1_PCTX`/`ASN1_SCTX`, and the 40 `*_it()` descriptors. |
| `asn1/d2i`, `i2d`, `fre`, `new`, `utl` | the shared decoder, encoder, free path, allocator and template support: the four `itype` arms, `CHOICE`, `ANY DEFINED BY`, `EMBED`, the `SET OF`/`SEQUENCE OF` writers, the `ASN1_ENCODING` cache and the reference count. |
| `asn1/text`, `time`, `a_print`, `a_mbstr`, `a_strex`, `a_strnid`, `a_utf8`, `t_pkey` | the text writers, the time family and the three `crypto/o_time.c` calendar symbols, the string classifiers, the mask-narrowing converter, the escaping printer, the per-NID string table, the UTF-8 codec and the two number printers. |
| `asn1/a_d2i_fp`, `a_i2d_fp`, `a_dup`, `asn_pack`, `a_type`, `evp_asn1`, `x_long`, `x_int64`, `x_bignum`, `asn1_gen`, `bio_asn1`, `asn_mime`, `tasn_prn` | the FILE/BIO bridges, `ASN1_dup`, `ASN1_item_pack`, the `ASN1_TYPE` operations, the four `ASN1_TYPE` octet-string pairs, the twelve primitive-hook items, `ASN1_generate_v3`, the ASN.1 filter BIO and the NDEF bridge, `asn_mime.c`'s copying half, and the structural printer. |
| `pem/pem_lib` | the two `pem.h` exports that need nothing but `BIO_snprintf`: `PEM_proc_type` and `PEM_dek_info`. |
| `runtime/err_sites` | 632 generated authority `ERR_raise` coordinates, including the `crypto/x509/v3_utl.c` and `crypto/asn1/asn_mime.c` sites a Phase 5 export can reach. |

## 3. The evidence

Each court is a C probe compiled twice — once against the admitted authority's headers
and library, once against the candidate's generated headers and `artifacts/phase2` —
run on the same machine, and diffed line by line on `key=value` so one divergence
produces exactly one residual instead of shifting every following line.

| court | observations | what it covers |
|---|---|---|
| `RT-BN` | 650 | the observable `BIGNUM`: values through the conversions, sign, bit length, predicates, return classes, the error queue after a failure, and the division identity `a == b*q + r`. |
| `RT-ASN1` | 1,403 | the DER header decoder over every boundary, the two's-complement codec, the string layer, the object layer, the text writers and the two parsers. |
| `RT-ASN1-TEMPLATE` | 100 | the template interpreter over a caller-built descriptor: `EMBED`, `OPTIONAL`, `CHOICE`, the `SET OF` canonical ordering, the twelve primitive-hook items, and the two `ASN1_TYPE` octet-string pairs. |
| `RT-ASN1-TIME` | 1,071 | the time family: both RFC 5280 syntaxes, the two type guards, the offset, the RFC 5280 profile, the four constructors, the calendar arithmetic, the diff-and-compare answers and the three printer formats. |
| `RT-ASN1-STR` | 5,831 | the string classification, the four-byte-per-character narrowing, the raw printer's 80-octet blocking, the mask-narrowing converter, the per-NID string table, the mask spellings and `ASN1_STRING_print_ex` over 23 flag sets and all 256 byte values. |
| `RT-ASN1-PRINT` | 275 | `ASN1_item_print` over every arm of its `itype` switch, including the `EMBED` re-addressing pinned at three values and the twenty-space indent blocks measured through a short-count sink. |
| `RT-BIO-ASN1` | 114 | the ASN.1 filter BIO as a write state machine, its prefix/suffix runs and callbacks, the four prefix/suffix controls, and `BIO_new_NDEF` over a caller-declared streaming item. |
| `RT-ASN1-MIME` | 188 | `SMIME_crlf_copy` under every flag combination, the buffering filter measured by logging each sink write, and `i2d_ASN1_bio_stream` with and without `SMIME_STREAM`. |
| `RT-PEM` | 37 | the two `pem.h` header formatters, including the conditional newline as the `PEM_BUFSIZE` buffer fills. |

## 4. What the courts found

Every section of this stratum was corrected by its own court, and the corrections are
the reason the courts exist rather than a by-product of them.

| decision | what the court found |
|---|---|
| D76 | A pre-decrement where the authority writes `if (max-- < 1)`, which rejected every object whose length was the last readable byte; two raise reasons that had been **typed rather than read** (`102`/`116`, not `101`/`127`); and `asn1_parse2` answering `1` for a failed parse. |
| D77 | Two defects in what D76 had landed — an unconditional free the authority makes conditional, and an `ASN1_R_TOO_SMALL` check that was absent — plus an ownership contract: a failed decode **frees the caller's value and nulls the caller's slot**. |
| D78 | `ASN1_ANY_it` and its siblings are exported but declared by no installed header, so the ownership atlas had to resolve them by name rather than by declaration. |
| D85 | `ASN1_TIME_print` calling the internal three-valued printer answered `-1` where the authority answers `0`, and only the public entry point could show it. |
| D86 | `ASN1_PRINT_MAX_INDENT` is **128**, not the 80 a plausible reading suggests — a constant recalled instead of read (the D33 class). |
| D87 | A `DUMP_DER` comparison of a non-character `ASN1_TYPE` contains a heap address and is not comparable; the probe was restricted to comparable types. |
| D88 | `ASN1_STRING_set_default_mask_asc("MASK:")` is refused by the authority before `strtoul` sees the empty remainder. |
| D89 | The three-call setup test of `BIO_new_NDEF`, rewritten as `setup * (cond <= 0)`, inverted the answer and produced a double free. Six lines transcribed would have been right. |
| D90 | `asn1_template_print_ctx` re-addresses an `EMBED` field through a local; the authority declares that local at function scope and the first version declared it inside the branch that fills it, so the pointer outlived its slot and the field printed a constant that was independent of its value. |
| D92 | `i2d_ASN1_bio_stream`'s unwind loop does not terminate in the authority when the streaming callback answers a BIO outside the chain back to `out`; the first version of the probe hung and the authority run had to be killed by the harness timeout. |

Three of those are worth generalising, because they are not about the code they
corrected. D86 is a constant recalled instead of read. D89 is the authority's own
lines rewritten into something tidier. D90 is a C idiom — a function-scope local whose
address is handed to a recursive call — translated into Rust with a narrower scope,
which compiles, reads plausibly, and points at a slot the compiler is entitled to
reuse. The first two are caught by reading more carefully; the third is caught only by
running both sides and noticing that a value does not depend on its input.

## 5. Fault boundaries — recorded, not reproduced

The stratum's divergences are in `docs/SECURITY_DIVERGENCE_POLICY.md` under their own
identifiers: `D-GF2M-1` and `D-GF2M-2` (the `BN_GF2m_*` blinding and carry chains),
`D-GENCB-1`/`D-GENCB-2` (the `BN_GENCB` null dereferences), `D-TIME-1`/`D-TIME-2` (the
time family's null dereferences and its wrapping calendar arithmetic), `D-PRINT-1`
(`ASN1_item_print` dereferences a null item and a malformed item), `D-MIME-1` (the
unbounded unwind loop), and `D-PEM-1` (`PEM_dek_info` calling `BIO_snprintf` with a
negative length converted to `size_t`).

The rule is the one the contract states and has not changed: an observable defined
behaviour is a compatibility target, and an authority memory fault, undefined
behaviour or non-termination is recorded instead of imported. No compatibility claim
covers any of them, and no probe reaches them, because a probe cannot compare a crash
or a hang.

## 6. What is explicitly NOT claimed

- Nothing about the 91 exports handed on. They are unimplemented, no probe calls them,
  and each names the dependency it waits for.
- Nothing cryptographic. `RT-BN` compares answers with the authority's; it does not
  establish that the arithmetic is sound, constant-time or side-channel resistant.
  `docs/PARITY_MODEL.md` records why OpenSSL differential evidence and cryptographic
  correctness are separate evidence planes, and the second one has not been run.
- Nothing about `libssl`, or about the 4,964 `libcrypto` exports still scaffolded.
- Nothing about a build profile other than the admitted one. `no-deprecated`, the
  legacy provider and FIPS-capable configurations are separate authorities that have
  not been built.
- Nothing about a platform other than Linux x86-64.
- Nothing about performance. `D-GF2M-2` is a recorded performance divergence, not a
  measured one.

## 7. Exit criteria

`docs/PHASE-5-SUBPHASES.md` defines closure as `open == 0`, the seal rewritten from
the ledgers, FRF `sensitivity-backed`, and a Gemel checkpoint. Each is now satisfied:

- `forensics/phase5-obligations.json` — `open_in_this_stratum: 0` and
  `implemented + deferred + open == owned`, asserted by the generator and reconciled
  by `ownership_audit.py`;
- `artifacts/phase5/COURTS.json` — `all_pass` true over 9 courts and 9,669
  observations;
- `forensics/phase-state.json` — phase 5 `complete`, with phases 0–4 already complete
  and no later stratum claiming completion first;
- this document, rewritten from those artefacts rather than from memory;
- the FRF claim and the Gemel checkpoint named in section 8.

## 8. FRF and Gemel

### FRF

The store was recreated from clean and the whole chain run end to end in the FRF
tooling container (`bash forensics/frf/run_courts.sh`) after the last commit of this
stratum. It holds 301 objects across 6 namespaces: 5 authorities, 108 captures, 72
challenges, 5 claims, 36 receipts and 75 residuals, with `graph_verified`,
`object_closure` and `stream_closure` all complete and `replay_ready` true. The
sensitivity-backed claim compiled over the runtime, ABI, CLI and inventory receipts is
`76a7f1e49a6548fe378d6bddf47ac21081b62dbd27731643b78f1abd9e831626`.

This stratum's receipts, one per court:

| court | receipt |
|---|---|
| `openssl-rs-rt-bn` | `receipt-run-openssl-rs-rt-bn-7738b53551f52ad95cb5a66e0a677032164d656e8cfdd7be3119e8c2906390fa-3d14a8e6f7e928c10dd5ea7e8d93807a90604d3d0c3c5fefbfd6948c5710aaf7` |
| `openssl-rs-rt-asn1` | `receipt-run-openssl-rs-rt-asn1-829d7d93dbac60a0f90172b8a25f23c733e1906bbddf75781843b6199fe9855f-c833ca84a130a3844ce4970eae38d53e2e2dddf842bdf091873719c9f75cd23a` |
| `openssl-rs-rt-asn1-template` | `receipt-run-openssl-rs-rt-asn1-template-5f7e8eb7b7fb11a7d20ed40354e0f5c7a23e8dc8a2c991073d06745e5213c54c-ab48f3b79e9c52a0050c4ea9d3caf6f71edc7960f8459e9abd01802a2eeb7489` |
| `openssl-rs-rt-asn1-time` | `receipt-run-openssl-rs-rt-asn1-time-c012ee85fe929f6fa313bd3260d2e37486faa33794b79b5129c4cd71157ddcdd-d6262fa757551fd687a519fac2e82f1cd599acc3433a001fddfda28b4d7001f3` |
| `openssl-rs-rt-asn1-str` | `receipt-run-openssl-rs-rt-asn1-str-e0bee3502b9313f7cfde27b46b529259cbbb92b34ef41acc5b85b073b7b1020f-9f75a3ffac035b987e19a46ff8d0a33f1ba2c608871eead3276d4fa6c47e84c8` |
| `openssl-rs-rt-asn1-print` | `receipt-run-openssl-rs-rt-asn1-print-b0192636051915caf8b1aa13e9b3fbd4994516f50384e2d65913258e3b536a5d-066585b1301afabf71f8479e0e9ac4294e142db3f02aa6de474182f00de85b03` |
| `openssl-rs-rt-bio-asn1` | `receipt-run-openssl-rs-rt-bio-asn1-7c12b79e8fe384bd8df3801a2b08cbba8c347c9ab90c8c79b8a8dac57a129397-34447e78597401f5cc47a1040a113324fb5907f261dc17b88674f096512bf379` |
| `openssl-rs-rt-asn1-mime` | `receipt-run-openssl-rs-rt-asn1-mime-87605f6f7dc55c375394555fdfe669c76a489e7328db7681f5334ceb67b72d75-bf973b39abf7a56008c4424c1317f66a348973a4b2a714b8bf4aadab02083721` |
| `openssl-rs-rt-pem` | `receipt-run-openssl-rs-rt-pem-8c5a3be9ac9adc32f0420deb3f5c09dba920c1fc2ce0d8a21ca779216ccec3a4-3a7bccd8246101bdc23b7e8881d02bdaa1aca012e6bb7c96dba600347ebe1fd0` |

The store is recreated from clean rather than appended to, because FRF's run identity
is content-addressed and does not vary with the rebuilt candidate's hash, so a fresh
observation requires a fresh store. **Every identity above moves with the store
generation**, which is why the identities are the ones on disk at this revision and
why a later revision of this section must re-read them rather than carry them
forward: an earlier revision of this seal quoted a superseded generation and that was
a defect. The `by-receipt` and `by-court` trees under `.frf/claims/` are the durable
form — they are keyed by receipt, not by claim hash.

`RT-ASN1-MIME`'s captures include **three** runs, not two: the passing run, plus the
two from the first version of the probe, one of which the harness killed at the
timeout. The killed run is the evidence for `D-MIME-1` and is committed rather than
discarded, because a hang that leaves a transcript and no exit is exactly the
observation that makes the divergence checkable.

A passing court is a differential result and nothing more. The claim above says the
candidate's transcript matched the authority's for the behaviours these probes
exercise, on one platform and for one build profile.

### Gemel

Recorded at this boundary as change `C43`
(`change.fc287d51e75a3f8bd782b9af4ae0ee2dc425b2693d30904554d7e5eb3fa1a0df`),
trajectory `T43`
(`trajectory.015d8e8f564c2ce730567dbc9bb1fadef0f39eecd04ef3662595f2d146dd8e2a`),
state `state.e37e2612ce18778003bd493480dcb5338c3f108bf61f91ee0ef5bad6f970e415`, and
checkpoint `K26`
(`checkpoint.4e8675a95b17554b5113e18653828e79c7c859cc37f7c3a2183a9c4864041d34`).
The previous boundary is change `C42`
(`change.cfe0615e499ed32f7eb925ca82d39a6c500b0d3de35530c6a22c5e6dfc431d07`) with
checkpoint `K25`
(`checkpoint.72f7fa3b2028e181c38bcb2d904f665cad991c15dfbe446629b3aee4147edc15`), the
`asn_mime.c` copying half, on trajectory `T42`.
Gemel names changes by derived order, so `C43` is not a stable identity and the
`change.` hash is; a name quoted elsewhere is resolved through
`forensics/GEMEL_TRAJECTORY.md` or `gemel show C43`. Each identity above was read back
from the store rather than carried forward. The store is append-only, so a correction
is another change rather than an edit, and the Git commit remains the authoritative
record of the diff.

Residuals recorded in the store at this boundary rather than left to be rediscovered:
the six `asn_mime.c` exports handed to Phases 7 and 12; the 31 RAND-dependent
`BN_*`/`ASN1_*` exports handed to Phase 9; the four `GF(2^m)` and `BN_GENCB`
divergences; the two `ABI_ONLY_EXPORTED` symbols the prototype court reports rather
rather than skipping; and `D-MIME-1`, whose reachability was established by measurement
and not by argument.

## 9. Correction from the ownership reconciliation (D97)

Appended, not folded in. This stratum's own evidence did not change, but two things
touching it did.

**One row left the hand-off list.** `BIO_f_asn1` and `BIO_new_NDEF` were recorded here
as discharged hand-offs from Phase 4. Both are declared in `asn1.h`, so the ownership
atlas gives them to this stratum **outright** -- they appear here as `implemented`
and always did. Listing them a second time as a received hand-off was an artifact of
the old Phase 4 ledger matching every `BIO_` name with a prefix. The four
`BIO_asn1_*` controls, which are declared in `bio.h`, are genuinely Phase 4's and
remain a real edge; both ledgers now record it and `ownership_audit.py` reconciles the
two readings in both directions.

**The derived state changed to `in-progress`.** Not on this stratum's evidence: its
ledger is at zero open and always was. D97 reopened Phases 3 and 4 after finding that
sixty-nine and nineteen of the exports the atlas assigns them had no ledger row at
all, and the dependency-order invariant says a phase may be complete only if every
earlier phase is. The stratum's own exit criteria in §7 stand unchanged.

Both corrections are recorded in `docs/DECISIONS.md` D97, and the arithmetic a reader
should cite is in `docs/SEAL-CENSUS.md`, which regenerates.

## 10. Correction: the signed encoders' fit rule (D104)

`BN_signed_bn2native`, `BN_signed_bn2bin` and `BN_signed_bn2lebin` take a destination
length, and this stratum's court exercised them with destinations that were obviously
large enough — which is exactly the case where the fit rule cannot be observed. Found by
Phase 6's `RT-PARAM`, whose builder path reaches `BN_signed_bn2native` with a *tight*
destination and whose output disagreed with the authority's.

The rule is in `crypto/bn/bn_lib.c`'s `bn2binpad`:

```c
n8 = BN_num_bits(a);
n  = (n8 + 7) / 8;                      /* BN_num_bytes */
ext = (n * 8 == n8) ? !a->neg : a->neg; /* the MSbit would be misread as a sign */
if (tolen == -1) tolen = n + ext;
else if (tolen < n + ext) { … if (tolen < n + ext) return -1; }
```

So a signed representation needs `n + ext` bytes, not `n`: one extra byte when the
magnitude fills its top byte exactly and the value is non-negative (`0x80` cannot be held
in one byte, because `0x80` there is `-128`), or when the magnitude does *not* fill its top
byte and the value is negative (`-1` needs two bytes — `0xff` is refused, `0xffff`
accepted). This module refused only when `BN_num_bytes(a) > tolen`.

Five destinations the authority refuses were accepted, and one it refuses was accepted as
a success with no write:

| value | `tolen` | authority | was |
|---|---|---|---|
| `-1` | 1 | refuse | wrote `ff` |
| `0x80` | 1 | refuse | wrote `80` |
| `-0x0102` | 2 | refuse | wrote `fefe` |
| `0xffff` | 2 | refuse | wrote `ffff` |
| `0` | 0 | refuse | returned 0 |

`RT-BN` now sweeps nineteen values — including `0`, `1`, `-1`, `0x7f`, `0x80`, `-0x80`,
`0xff`, `-0xff`, `0x0102`, `-0x0102`, `0x7fff`, `0x8000`, `-0x8000`, `0xffff`, `-0xffff`,
`0x010000`, `-0x010000` and three multi-limb shapes — against every `tolen` from 0 to 5,
for all three entry points, plus a negative `tolen` and the `BN_signed_native2bn` inverse.
That is 860 further observations and it is what makes the rule checkable rather than
asserted. Its first run after the fix is byte-identical to the authority's.

The stratum gains no export and its ledger is unchanged at zero open, so it remains
`complete`; this section is the correction, not a reopening. The lesson is the one §9 and
`docs/DECISIONS.md` D96 record from other angles: **a court's coverage is a property of
the inputs it chooses**, and "obviously large enough" is a choice.
