# Phase 8 — the native cryptographic primitives, as subphases

## 0. What this stratum is, and what it is not

Phase 8 is the **algorithm** half of `libcrypto`'s public surface: the digest
constructions, the symmetric ciphers and their modes, and the four asymmetric key types
(`RSA`, `DH`/`DHX`, `DSA`, `EC`) together with the ASN.1 method objects that give them
names. Seven hundred and fifty-nine exports are assigned to it by
`forensics/atlas/symbol-ownership.json`, plus twenty-seven that Phase 7 handed over —
seven hundred and eighty-six rows in total.

It is **not** the plumbing. The fetch layer, the method stores, the `EVP_*` object families
and the `EVP_PKEY` layer are Phase 7's, and this stratum is written *against* them: a
digest here is two things, the construction over the caller's bytes and the
`OSSL_OP_DIGEST` implementation a provider publishes, and only the first of those existed
before Phase 7 sealed. Nor is it the random layer, the key encoders, the X.509 world or the
TLS protocol: `RAND`/DRBG is Phase 9's, `OSSL_ENCODER_*`/`OSSL_DECODER_*` and the key
formats are Phase 10's, and the assembly fast paths are Phase 19's
(`docs/RELEASE_GATES.md` puts "Performance / CPU dispatch" there).

Three consequences are worth stating before the subphase table, because each one is a
measurement rather than a plan:

* **The exported digest API is C, and only its block function is perlasm.** Intersecting
  every `libcrypto-shlib-*.o` under the build tree with this stratum's export set (the
  method §1 describes) puts **zero** of the `md5-x86_64`, `sha1-x86_64`, `sha256-x86_64`,
  `sha512-x86_64`, `wp-x86_64`, `sm3-x86_64` and `keccak1600-x86_64` objects' definitions
  in the Phase 8 export set. What those objects provide is `md5_block_data_order`,
  `sha256_block_data_order` and their siblings, which the version script hides. So for
  8.1 the assembly is an *internal* alternative implementation of a function the crate
  must also have, and `SHA256_Init`'s `OPENSSL_ia32cap` dispatch is invisible to a probe
  compiled against the installed headers.
* **The same is not true of 8.2, and the difference is a fact about the exported
  symbols rather than about assembly.** `crypto/aes/asm/aes-x86_64.pl`'s object defines
  **five** exports (`AES_cbc_encrypt`, `AES_decrypt`, `AES_encrypt`,
  `AES_set_decrypt_key`, `AES_set_encrypt_key`), `crypto/rc4/asm/rc4-x86_64.pl`'s
  defines three (`RC4`, `RC4_options`, `RC4_set_key`) and
  `crypto/camellia/asm/cmll-x86_64.pl`'s defines one (`Camellia_cbc_encrypt`). Nothing in
  this stratum's plan may treat those nine as "the C implementation with an optional fast
  path": in the authority they *are* the symbol, and the differential court is the only
  instrument that can say whether the crate's portable arm answers the same bytes.
* **Phase 8 owns glue that lives in other directories, and Phase 7 says so.** All
  thirty of `pem.h`'s are `crypto/pem/pem_all.c`'s, and `crypto/pem/pem_all.c` is Phase
  5's translation unit, not this stratum's; the RSA, DH, DSA and EC
  `EVP_PKEY_CTX_set_*` families are declared in `rsa.h`, `dh.h`,
  `dsa.h` and `ec.h` and their bodies are `crypto/{rsa,dh,dsa,ec}/*_pmeth.c`'s. Ownership
  follows the *header that promises the symbol*, which is the atlas's rule (D72) and not
  the directory a file was written in.

## 1. The measurement this plan rests on

The authority's build tree holds one `.o` per translation unit per form
(`libcrypto-shlib-<stem>.o`), so which unit defines which export is a **measurement** and
not an inference. Listing every one under
`forensics/authorities/build/openssl-3.6.4-production` — 845 objects — and intersecting
each one's defined externals with the atlas's Phase 8 set places **759 of 759** across
**143 units**: no export in this stratum is unaccounted for by a translation unit. The
largest are:

| unit | Phase 8 exports | unit | Phase 8 exports |
|---|---|---|---|
| `crypto/ec/ec_lib.c` | 69 | `crypto/dh/dh_ctrl.c` | 20 |
| `crypto/rsa/rsa_lib.c` | 57 | `crypto/ec/ec_kmeth.c` | 19 |
| `crypto/ec/ec_key.c` | 34 | `crypto/rsa/rsa_asn1.c` | 19 |
| `crypto/rsa/rsa_meth.c` | 33 | `crypto/ec/ec_ctrl.c` | 12 |
| `crypto/pem/pem_all.c` | 30 | `crypto/dsa/dsa_sign.c` | 11 |
| `crypto/dsa/dsa_meth.c` | 27 | `crypto/modes/gcm128.c` | 11 |
| `crypto/ec/ec_asn1.c` | 27 | `crypto/modes/ocb128.c` | 10 |
| `crypto/dh/dh_lib.c` | 25 | `crypto/rsa/rsa_crpt.c` | 10 |
| `crypto/dsa/dsa_lib.c` | 24 | `crypto/modes/ccm128.c`, `cts128.c` | 8 each |
| `crypto/dh/dh_meth.c` | 21 | `crypto/dh/set_key.c`, `dsa_asn1.c`, `dsa_ctrl.c` | 7 each |

and the remainder is one hundred and twenty-odd units of one to six exports each.
**The count is a measurement, not a plan:** the plan below groups them by *dependency*, and
the subphase boundaries are drawn where a build can be verified rather than where the file
list happens to break.

By declaring header the stratum is twenty-two headers:

| header | exports | header | exports | header | exports |
|---|---|---|---|---|---|
| `ec.h` | 199 | `pem.h` | 30 | `cast.h`, `rc2.h`, `seed.h` | 7 each |
| `rsa.h` | 154 | `sha.h` | 23 | `md4.h`, `md5.h`, `ripemd.h`, `whrlpool.h` | 5 each |
| `dh.h` | 94 | `aes.h` | 15 | `mdc2.h` | 4 |
| `dsa.h` | 87 | `camellia.h` | 10 | `rc4.h` | 3 |
| `modes.h` | 50 | `blowfish.h`, `idea.h` | 8 each | `evp.h` (handed in) | 27 |
| `des.h` | 33 | | | | |

By library: `libcrypto` 759, `libssl` 0 — Phase 8 adds nothing to `libssl`. The extra
`evp.h` row is the hand-off described below, and it is deliberately *not* part of the
twenty-two: those are the headers the atlas assigns this stratum, and `evp.h` is Phase 7's.

### The twenty-seven hand-offs arriving from Phase 7

Phase 7's `forensics/phase7-obligations.json` records twenty-seven rows whose
`owning_phase` is 8, and every one of them is `evp.h`'s:

```text
EVP_PKEY_get0_RSA  get1_RSA  set1_RSA      EVP_PKEY_get0_DH   get1_DH   set1_DH
EVP_PKEY_get0_DSA  get1_DSA  set1_DSA      EVP_PKEY_get0_EC_KEY get1_EC_KEY set1_EC_KEY
EVP_PKEY_assign    EVP_PKEY_type           EVP_PKEY_meth_find  _get0  _get_count
EVP_PKEY_get0_hmac poly1305 siphash        EVP_PKEY_encrypt_old  decrypt_old
EVP_PKEY_get_ec_point_conv_form            EVP_PKEY_get_field_type
d2i_PublicKey  d2i_KeyParams  d2i_KeyParams_bio
```

Their reason is one mechanism and not twelve: each takes the **legacy** route — a
downgraded `RSA`/`DH`/`DSA`/`EC_KEY`, or a search of `standard_methods[]` — and neither the
four types nor the table exists yet. That is why D164 handed them forward and why **8.8 is
the subphase that discharges them**: the table's contents are `crypto/asn1/ameth_lib.c`'s,
and its twelve objects are `crypto/{rsa,dh,dsa,ec}/*_ameth.c`'s. `ownership_audit.py`
reconciles the two readings in both directions, so an edge recorded on one side only fails
the audit; at the bootstrap it reads the Phase 7 → 8 edge with `mismatched: 0`.

### The one deferral this stratum discharges on arrival, and the seven it owes

`forensics/prerequisites.json` currently carries seven rows whose `owner_phase` is 8:
`evp_cleanup_int` (`crypto/evp/names.c`'s, retargeted here by D196 because its seventh call
is `evp_app_cleanup_int`), `evp_pkey_get_legacy`, `evp_pkey_get0_DH_int`,
`evp_pkey_copy_downgraded`, `evp_app_cleanup_int`, `ossl_rsa_asn1_meths` and
`ossl_rsa_pkey_method`. The first five are the legacy-key path 8.4-8.7 make reachable; the
last two are the `EVP_PKEY_ASN1_METHOD` and `EVP_PKEY_METHOD` halves of the RSA method
objects 8.8 builds. **None is discharged at the bootstrap**, and the gate reports them as
`planned_prerequisites` rather than as gaps, which is the census it publishes for exactly
this state.

## 2. The subphases

Ordering is by dependency, and each row's dependency column was read from the authority's
calls rather than from the export list — the method D114, D118 and D122 established.

The **"Open at the split"** column is a *measurement*: it is the number of rows this
subphase's module labels hold in `forensics/phase8-obligations.json`'s `open` list on the
day the split was made, which is the bootstrap commit. It is a census of what was open
then and not a claim about the present; the ledger is what says what is open now.

| # | Subphase | Owns | Depends on | Courts | Open at the split |
|---|---|---|---|---|---|
| 8.0 | **Bootstrap** | nothing in the crate — evidence: `docs/PHASE-8-SUBPHASES.md`, `forensics/tools/phase8_obligations.py`, `forensics/tools/phase8_courts.py`, `courts/phase8/`, and this stratum's row in `forensics/tools/phase_state.py`'s `STRATUM_EVIDENCE` | 7 | — | 770 |
| 8.1 | **The digest primitives** | MD4, MD5, MDC2, RIPEMD-160, Whirlpool, SM3, SHA-1, SHA-2 (224/256/384/512/512-224/512-256), SHA-3 (224/256/384/512) and SHAKE-128/256: the low-level `X_Init`/`_Update`/`_Final`/`_Transform` API **and** the provider `OSSL_OP_DIGEST` implementations, plus the digest half of `ossl_default_provider_init`. Forty-seven labels: `src/digest/{md4,md5,mdc2,ripemd,wp,sha1,sha2}.rs` | 8.0 | `RT-DIGEST`, `CT-DIGEST` | 47 |
| 8.2 | **The symmetric cipher primitives** | AES (all modes), DES/3DES, RC2, RC4, Blowfish, CAST5, IDEA, SEED, Camellia, SM4, ARIA, and `modes.h`'s `CRYPTO_*` helpers; the low-level API **and** the provider `OSSL_OP_CIPHER` implementations + the cipher half of the default provider. Ninety-eight labels across `src/des/mod.rs`, `src/aes.rs`, `src/camellia.rs`, `src/blowfish.rs`, `src/cast.rs`, `src/idea.rs`, `src/rc2.rs`, `src/rc4.rs`, `src/seed.rs`. **LANDED (D209–D223), and checked against the ledger by D208's gate.** Every low-level export this row names is in, and the cipher half of `ossl_default_provider_init` now answers `OSSL_OP_CIPHER`: `src/provider/cipher.rs` publishes `deflt_ciphers[]`'s AES, Camellia, 3DES and `NULL` rows (each alias verbatim from `prov/names.h`, each row's provider checked against `defltprov.c`), driven by a transcription of `ciphercommon.c.in`/`ciphercommon_hw.c`/`ciphercommon_block.c`. **SM4 and ARIA have no low-level API and no `src/sm4.rs`/`src/aria.rs`** (D209 §2: the authority exports no `SM4_*`/`ARIA_*`), so their rows are provider-only and are not among this row's labels. The AEAD (GCM/CCM/XTS/OCB/SIV/wrap), CTS, `ChaCha20`, ARIA/SM4 and asm-selected `cipher_aes_cbc_hmac_*` rows are 8.3's or absent by design; `deflt_get_params`/`deflt_gettable_params`/`ossl_prov_get_capabilities`/`provctx` and the `base`/`null` providers are still absent. | 8.1 | `RT-CIPHER`, `CT-CIPHER` | 97 |
| 8.3 | **The AEAD and mode primitives** | GCM, CCM, XTS, key wrap, Poly1305, ChaCha20-Poly1305, and the remaining `CRYPTO_*` mode functions. Fifty labels, all of them `src/modes/mod.rs`'s. **The low-level half is LANDED (D224–D229):** all fifty `modes.h` exports are in — key wrap (D224), GCM (D225), CCM (D226), XTS (D227) and OCB (D229) — and their evidence is the `RT-CIPHER`/`CT-CIPHER` families this row names. Poly1305 and ChaCha20-Poly1305 are **not** this stratum's exports (D228): they are internal units (`crypto/poly1305/poly1305.c`, `crypto/chacha/chacha_enc.c`) and provider rows, with no `libcrypto` symbol. **The provider half has begun (D230–D233), and its first AEAD engine of its own is in (D238):** `deflt_ciphers[]` now publishes the twelve AES key-wrap rows, the six CBC-CTS rows (AES-128/192/256 and Camellia-128/192/256, D231), the two AES-XTS rows (D232), the three AES-OCB rows (D233) and the three AES-CCM rows (D238, with `ciphercommon_ccm.c`'s engine transcribed whole and its failure arms raising the authority's own provider reasons), leaving ChaCha20 open; the AES-GCM rows are **deferred to Phase 9** because their no-IV encrypting arm and their TLS arm both call RAND_bytes_ex (D234), and D241 discharged the **second** blocker D240 had found there — `ossl_cipher_generic_initkey` stores `PROV_LIBCTX_OF(provctx)` on `ctx->libctx`, and so do the two AEAD rows that acquire it at `newctx` instead because their own `initkey` never reaches the generic one, so a provider row's sub-fetches and its `RAND_bytes_ex(ctx->libctx, …)` calls resolve in the library context of the provider that created the row. That discharge is measured rather than asserted: `forensics/atlas/provider-algorithms.json`'s `provider_context` block classifies every one of the authority's 26 acquisition sites and anchors each landed one **inside the crate function that owes it**, and `RT-CIPHER`'s private-`OSSL_LIB_CTX` arm observes the scoping (D241, D242). **The SIV rows are LANDED (D241):** the prerequisite D239 measured is discharged — `providers/implementations/macs/cmac_prov.c` is transcribed (`src/provider/mac.rs`, with `CMAC_FUNCTIONS` and the default provider's two CMAC rows), so `EVP_MAC_fetch(NULL, "CMAC", NULL)` now answers 1 on both sides where D239 measured 0 on the candidate, and the three AES-SIV cipher rows follow on top of it (`cipher_aes_siv.c`'s engine driven by `src/modes/siv128.rs`), with RFC 5297 Appendix A.1 as a known-answer arm. Eight of Phase 8's nine `OSSL_OP_MAC` rows are still open. | 8.2 | `RT-CIPHER`, `CT-CIPHER` | 50 |
| 8.4 | **RSA** | the `RSA` object and `RSA_*`, `ossl_rsa_asn1_meth`, and the RSA provider keymgmt/signature/asymcipher/asym-kem. One hundred and fifty-seven labels: `src/rsa/mod.rs` | 8.1 (the RSA provider's `SHA`-named digests), 8.3 (its OAEP/PSS modes) | `RT-RSA`, `CT-RSA` | 150 |
| 8.5 | **DH and DHX** | the `DH` object, `DH_*`, `ossl_dh_asn1_meth`, the FFC groups, and the DH provider surfaces. Ninety-seven labels: `src/dh/mod.rs` | 8.4 (the shared BN/param idiom) | `RT-DH`, `CT-DH` | 93 |
| 8.6 | **DSA** | the `DSA` object, `DSA_*`, `ossl_dsa_asn1_meth`, and the DSA provider surfaces. Ninety labels: `src/dsa/mod.rs` | 8.5 | `RT-DSA`, `CT-DSA` | 88 |
| 8.7 | **EC** | `EC_KEY`, `EC_GROUP`, `EC_POINT`, the curve tables, `ossl_ec_asn1_meth`, and the EC provider surfaces. Two hundred and two labels: `src/ec/mod.rs` | 8.6 | `RT-EC`, `CT-EC` | 200 |
| 8.8 | **The ASN.1 method objects and `standard_methods[]`** | `crypto/asn1/ameth_lib.c`'s table and the `ossl_*_asn1_meth` objects — **this is what retires the 27 Phase-8 rows in Phase 7's `deferred_by_phase` and the `EVP_PKEY_type`/`d2i_*`/`EVP_PKEY_meth_*` blockers**. Fifteen labels, the fifteen `evp.h` hand-offs that are not a key type's accessor: `src/asn1/ameth.rs` | 8.4, 8.5, 8.6, 8.7 | `RT-AMETH` | 15 |
| 8.9 | **The `pem.h` helpers Phase 8 owns** and the `*_asn1_meth` bodies that unblock Phase 7's remaining Phase-8 deferrals | the thirty `pem.h` names — the `PEM_read_*`/`PEM_write_*` family for `DHparams`, `RSA`, `DSA` and `EC` keys. Thirty labels: `src/pem/key_legacy.rs` | 8.8 | `RT-PEM-KEY` | 30 |
| 8.10 | **The seal** | nothing in the crate — evidence: `docs/PHASE-8-CRYPTO-SEAL.md` | 8.0–8.9 | — | 0 |

The nine rows above the seal hold 786 rows between them — 47 + 98 + 50 + 157 + 97 + 90 +
202 + 15 + 30 — and `open` at the split is 770 of them, because **sixteen** are the recorded
hand-offs below. Eight of the subphases will split as they land (8.4 and 8.7 are each over
one hundred and fifty exports), and the precedent from Phase 6 and Phase 7 is that a split
is recorded here with the reason it was needed rather than performed silently.

### Every primitive-bearing row carries two courts, because a primitive has two questions

**Doctrine.** For a compatibility port the authority oracle dominates, and for most of this
stratum's surface one differential court is the strongest instrument there is. A
**cryptographic primitive** is the one place where a second, independent plane answers a
different question, and neither plane implies the other:

```text
RT-<X>   OpenSSL differential      -> "does it behave like the admitted authority?"
CT-<X>   construction/spec vectors -> "does it satisfy the underlying construction?"
```

`RT-*` is the differential court §0's "the method" describes: one probe compiled twice, the
two `key=value` transcripts diffed. It decides **compatibility**. `CT-*` is the
correctness-vector court: the crate's implementation, through the same candidate distribution
shell, is run against committed vectors whose provenance is recorded per vector, and the
verdict is per-vector and loud. It decides **correctness against a published construction**.

**Why two planes are needed.** Each plane has a blind spot the other covers.

* **An `RT-*` pass is not independent cryptographic correctness.** Two implementations can
  agree byte for byte and both be wrong against the standard: a round constant read from the
  same wrong place, a message-word order transcribed the same wrong way. The differential
  compares the candidate with *the authority*, and a transcription error in a shared reading
  of the authority's own text makes the two agree on the wrong answer. What rules that out is
  a *second, independent statement of the expected bytes* — a value the standard publishes,
  which no transcription of the implementation can move.
* **A `CT-*` pass is not OpenSSL parity.** A portable arm can satisfy every published vector
  and still differ from the authority in an observable way — a `Transform` that advances a
  different number of bytes, a context field the authority leaves and this one clears, an
  error return the vector set never exercises. The vector set does not contain the
  authority's behaviour; the differential transcript does.

**What the second plane's independence is, said precisely.** It is **candidate-only
construction verification using standard-derived vectors mirrored in the pinned OpenSSL test
corpus**. The probe is compiled against the candidate alone; the expected bytes are values
the standards publish (RFC 1320 §A.5, RFC 1321 §A.5, FIPS 180-4 / RFC 6234 §8.5,
ISO/IEC 10118-3, the Rijmen–Barreto Whirlpool submission); and the bytes are mirrored through
the pinned authority's own `test/recipes/30-test_evp_data/evpmd_*.txt`. That is *data
independence*: a transcription error in the implementation cannot move the vectors. It is
**not** independence from the pinned tree, because that tree is where this repository reads
the mirror — a reader who wants an oracle this repository never read must supply one. For a
vector whose input no standard publishes (the padding boundaries), the expected bytes come
from an implementation that is neither the crate nor the pinned authority build, the oracle
is named in the vector's provenance, and `UNKNOWN` is a valid provenance value.

**What each does *not* establish, stated so neither is read as the other.**

| plane | establishes | does **not** establish |
|---|---|---|
| `RT-DIGEST` and its siblings | that the candidate's observable transcript matches the authority's for the behaviours the probe exercises | cryptographic correctness — a shared transcription error agrees with itself — and any behaviour the probe does not touch |
| `CT-DIGEST` and its siblings | that the candidate's construction produces the committed expected bytes for every vector and update mode, over the inputs those vectors cover | OpenSSL parity; and it is **not formal validation** — published test vectors are informal verification, not a certificate. NIST CAVP and Project Wycheproof are **declined with reason** (they need the network, and the vectors here are already in the pinned tree with a primary source named), not relied on |

**What this changes, and what it does not.** The `RT-*` requirement is not weakened: it is
still the only instrument that can say the candidate is *this* implementation's observable
behaviour, which §3's first row says a portable arm over perlasm needs. What changes is that
it is no longer stated as *instead of* vectors. §3's first row and §4's second gate are amended
to say both. And a `CT-*` court that cannot run yet is **not** registered as passing: it is
named in `forensics/tools/phase8_courts.py`'s `PENDING_CORRECTNESS_COURTS` with what it needs,
which is what "not run yet" has to look like in a runner whose only other states are pass and
fail.

**The courts, named.** `RT-DIGEST`/`CT-DIGEST` (8.1), `RT-CIPHER`/`CT-CIPHER` (8.2),
`RT-MODES`/`CT-MODES` (8.3), `RT-RSA`/`CT-RSA` (8.4), `RT-DH`/`CT-DH` (8.5),
`RT-DSA`/`CT-DSA` (8.6), `RT-EC`/`CT-EC` (8.7). 8.8 (`RT-AMETH`) and 8.9 (`RT-PEM-KEY`) are
not given a `CT-*` court, and the reason is a boundary rather than an omission: they are the
ASN.1 method objects and the `PEM_*` key helpers, and what a *method object* must do is
*defined* by the authority's own behaviour — the version node, the callback wiring — not by a
construction vector over a value. If a later slice gives one of them a construction with a
published vector, the court arrives with it.

**The driver shape, and why it is a second registry.** A correctness court runs the crate
**only**: there is no authority transcript, so there is nothing to diff and the differential
runner's shape does not apply. `forensics/tools/correctness_vectors.py` owns the vector schema
and the per-vector comparison, and `forensics/tools/phase8_courts.py` carries a second
registry (`CORRECTNESS_COURTS`) beside its differential one (`COURTS`). The two are separate
because they are different shapes; folding a candidate-only court into the differential list
would have hidden which of the two comparisons a green verdict came from.

**The exemplar, and its first result is a failure.** `CT-DIGEST` is wired for the nine digest
constructions 8.1a implements, over committed vectors extracted from the pinned authority's own
`test/recipes/30-test_evp_data/evpmd_*.txt` (the per-construction counts and update modes live
in `forensics/vectors/*.json`, and the plane has since grown past this first one-message shape --
D206). Against the 8.1a tree this amendment lands with, `artifacts/phase8/COURTS.json` recorded
**24 of 41 vectors passing and 17 failing**: MD4 0/7, SHA-1 0/2 and Whirlpool 0/8 failed, while
MD5 7/7, RIPEMD-160 8/8 and the SHA-2 family 9/9 passed. That is the independent plane
doing its job: the same three constructions this stratum's WIP commit (`bd4c9914`) records as
failing are the three the vectors find, per input. The failing vectors are recorded in full in
`docs/DECISIONS.md` D201, and fixing the implementation is the next content slice — deliberately
not the slice that added the plane.

### 8.1's row names MDC2, and MDC2 cannot be written before 8.2

**D197.** The row above is a dependency-ordered boundary, and reading 8.1's own units
against each other says that one of them is on the wrong side of it. MD4, MD5, RIPEMD-160,
Whirlpool, SHA-1 and the SHA-2 family are self-contained: their bodies are a message
schedule, a compression function and the collector `include/crypto/md32_common.h`
implements. **`crypto/mdc2/mdc2dgst.c`'s `mdc2_body` is not.** It calls three `des.h`
exports:

```text
crypto/mdc2/mdc2dgst.c:79   DES_set_odd_parity(&c->h);
crypto/mdc2/mdc2dgst.c:80   DES_set_key_unchecked(&c->h, &k);
crypto/mdc2/mdc2dgst.c:81   DES_encrypt1(d, &k, 1);
```

and two more for the second lane at `:84`, `:85`. Those three are 8.2's — MDC2 is
DES-based by construction, which is what its name says — so MDC2 is **not** in 8.1's
landing set and its four labels stay in the ledger's `open` list until 8.2 lands the DES
key schedule and round function. Two options were available and both were rejected: landing
the three DES functions early puts 8.2's first work in 8.1's commit for a reason the row
does not name, and writing MDC2 over a private DES would be a second implementation of a
symbol this stratum exports once. The dependency is recorded here instead, which is the
disposition 7.4's own inversion received (D163).

### 8.1's brief names a SHA-3, SHAKE and SHA-512/224 API this authority does not export

The same reading settles three more of 8.1's names, and it is a measurement rather than a
reading of the version script's intent. The authority's `include/openssl/sha.h` is 139
lines and declares **no** `SHA3_*`, no `SHAKE*`, no `SHA512_224`/`SHA512_256` and no
`SHA256_192` function; `forensics/atlas/openssl-3.6.4-production/symbols-libcrypto.json`
has no record for `SHA3_absorb`, `SHA3_squeeze` or `SHA3_256` either, and
`crypto/sha/sha3.c`'s four entry points are `ossl_sha3_reset`, `ossl_sha3_init`,
`ossl_sha3_update`, `ossl_sha3_final` and `ossl_sha3_squeeze`, of which **none** is
exported. What the authority *does* export for those constructions is the `EVP_MD` name:
`EVP_sha3_224`…`EVP_sha3_512`, `EVP_shake128`, `EVP_shake256`, `EVP_sha512_224`,
`EVP_sha512_256` and `EVP_sm3` are all in the Phase 7 export set and are already
implemented there.

So 8.1's SHA-3, SHAKE, SHA-512/224, SHA-512/256, SHA-256/192 and SM3 work is **provider
work with no low-level export to land**, and the internal entry points it needs are the
`ossl_*` names above plus `sha512_224_init`/`sha512_256_init`/`ossl_sha256_192_init`
(`crypto/sha/sha512.c`, `crypto/sha/sha256.c`) and `ossl_sm3_init`/
`ossl_sm3_block_data_order` (`crypto/sm3/sm3.c`). They carry no `#[no_mangle]` for the
reason 7.3's internals do not: a symbol that is `local` in the authority is `local` here.
The plan says so per construction rather than letting a reader expect a `SHA3_256_Init`
that the authority never had.

### The five SHA one-shots are `EVP_Q_digest`, and that makes them 8.1's provider half

The other half of the same reading, and it is the one that decides the order *inside* 8.1.
Of the seven digest one-shots this stratum owns, five are **not** one-shot constructions at
all:

```text
crypto/sha/sha1_one.c:36   SHA1(d,n,md)    ->  EVP_Q_digest(NULL, "SHA1",   NULL, d, n, md, NULL)
crypto/sha/sha1_one.c:46   SHA224(...)     ->  EVP_Q_digest(NULL, "SHA224", ...)
crypto/sha/sha1_one.c:54   SHA256(...)     ->  EVP_Q_digest(NULL, "SHA256", ...)
crypto/sha/sha1_one.c:62   SHA384(...)     ->  EVP_Q_digest(NULL, "SHA384", ...)
crypto/sha/sha1_one.c:70   SHA512(...)     ->  EVP_Q_digest(NULL, "SHA512", ...)
```

`EVP_Q_digest` is Phase 7's and is implemented, but it fetches through the **default
library context**, and the candidate has no default provider: `ossl_default_provider_init`
does not exist, which is the residual `docs/DECISIONS.md` D117 records. `MD4`, `MD5`,
`RIPEMD160`, `MDC2` and `WHIRLPOOL` are one-shots in the older sense —
`crypto/md5/md5_one.c` calls `MD5_Init`/`_Update`/`_Final` directly — so they land with
their construction and the five `sha.h` one-shots land with the provider.

**That is the drop-in-replacement payoff of this subphase, and it is why the provider half
is not an appendix to 8.1.** Landing the digest half of `ossl_default_provider_init` makes
`EVP_MD_fetch(NULL, "SHA256", NULL)` resolve, which makes `SHA256_Init`'s public spelling
work and retires the D117 residual for digests. 8.1 therefore lands in two slices, and the
split is recorded here rather than performed silently:

| # | Land | Open at the split |
|---|---|---|
| 8.1a | the low-level constructions and their collector: `MD4`, `MD5`, `RIPEMD160`, `WHIRLPOOL` whole (Init/Update/Final/Transform and the one-shot), `SHA1`/`SHA224`/`SHA256`/`SHA384`/`SHA512`'s `Init`/`Update`/`Final`/`Transform` — **thirty-eight exports** — and its two courts, `RT-DIGEST` and `CT-DIGEST` | 38 |
| 8.1b | the provider half: `PROV_DIGEST` and `digestcommon.c`'s `ossl_digest_default_get_params`/`_gettable_params`, the `*_prov.c` dispatch tables, the `sm3`/`sha3`/`keccak1600` internals, the five `sha.h` one-shots, and the digest half of `ossl_default_provider_init` with `providers/defltprov.c`'s `deflt_digests[]`. MDC2's four labels are **not** here: they are 8.2's, per the DES inversion above. **PARTLY LANDED (D206):** the digest half of `ossl_default_provider_init` is declared and reachable — `src/provider/digest.rs` publishes the seven default-provider rows whose constructions 8.1a built (`SHA1`/`SHA224`/`SHA256`/`SHA384`/`SHA512`, `MD5`, `RIPEMD160`) and the fallback walk now activates `default`, so `EVP_MD_fetch(NULL, "SHA256", NULL)` resolves and `EVP_DigestInit_ex`/`_Update`/`_Final_ex` operate through it. `MD4` and `WHIRLPOOL` are deliberately **not** among the rows: the author's constructions exist, but the authority publishes them from the legacy provider (Phase 13's, per `forensics/prerequisites.json`) and not from the default provider, so `EVP_MD_fetch(NULL, "MD4", NULL)` answers NULL without a legacy provider and `RT-DIGEST` observes the pair. **LANDED (D207, and checked against the ledger by D208's gate).** The `sm3`/`sha3`/`keccak1600` internals, the SHA-3/SHAKE/SM3/BLAKE2/`md5_sha1`/`null` digest rows, the two truncated SHA-512 spellings and SHA2-256/192, and the five `sha.h` one-shots are all in; what remains of Phase 8 is its other subphases' work, not 8.1's. | 5 |

### 8.1's status, checked against the ledger

`forensics/phase8-obligations.json` is the arithmetic for what a stratum has landed, and this
subphase's status is stated against it rather than in prose that can outrun it. The two clauses
below are anchored: `docs_consistency.py` reads the symbols out of them and compares each with the
ledger, in **both** directions -- a symbol claimed landed must be in `implemented`, and a symbol
claimed open must be in `open`. They are a *sample* that spans the subphase and not an
enumeration, so a symbol landing without being added here is not a failure; a symbol *misstated*
here is. (`forensics/phase8-obligations.json` remains the only complete list.)

**Landed exports (checked against the ledger):** `SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`,
`MD4_Init`, `MD4_Update`, `MD4_Final`, `MD4_Transform`, `MD4`, `MD5_Init`, `MD5_Update`,
`MD5_Final`, `MD5_Transform`, `MD5`, `RIPEMD160_Init`, `RIPEMD160_Update`, `RIPEMD160_Final`,
`RIPEMD160_Transform`, `RIPEMD160`, `WHIRLPOOL_Init`, `WHIRLPOOL_Update`, `WHIRLPOOL_Final`,
`WHIRLPOOL`, `CRYPTO_cbc128_encrypt`, `CRYPTO_cbc128_decrypt`, `CRYPTO_ctr128_encrypt`,
`CRYPTO_ctr128_encrypt_ctr32`, `CRYPTO_ofb128_encrypt`, `CRYPTO_cfb128_encrypt`,
`CRYPTO_cfb128_8_encrypt`, `CRYPTO_cfb128_1_encrypt`, `CRYPTO_cts128_encrypt`,
`CRYPTO_cts128_encrypt_block`, `CRYPTO_cts128_decrypt`, `CRYPTO_cts128_decrypt_block`,
`CRYPTO_nistcts128_encrypt`, `CRYPTO_nistcts128_encrypt_block`, `CRYPTO_nistcts128_decrypt`,
`CRYPTO_nistcts128_decrypt_block`, `AES_set_encrypt_key`, `AES_set_decrypt_key`, `AES_encrypt`,
`AES_decrypt`, `AES_ecb_encrypt`, `AES_cbc_encrypt`, `AES_cfb128_encrypt`, `AES_cfb1_encrypt`,
`AES_cfb8_encrypt`, `AES_ofb128_encrypt`, `AES_ige_encrypt`, `AES_bi_ige_encrypt`,
`AES_wrap_key`, `AES_unwrap_key`, `AES_options`, `RC4_set_key`, `RC4`, `RC4_options`,
`DES_set_key`, `DES_set_key_checked`, `DES_set_key_unchecked`, `DES_key_sched`,
`DES_set_odd_parity`, `DES_check_key_parity`, `DES_is_weak_key`, `DES_options`,
`DES_encrypt1`, `DES_encrypt2`, `DES_encrypt3`, `DES_decrypt3`, `DES_ecb_encrypt`,
`DES_ecb3_encrypt`, `DES_cbc_encrypt`, `DES_ncbc_encrypt`, `DES_pcbc_encrypt`,
`DES_xcbc_encrypt`, `DES_cfb64_encrypt`, `DES_ede3_cfb64_encrypt`, `DES_ede3_cfb_encrypt`,
`DES_cfb_encrypt`, `DES_ofb_encrypt`, `DES_ofb64_encrypt`, `DES_ede3_ofb64_encrypt`,
`DES_ede3_cbc_encrypt`, `DES_cbc_cksum`, `DES_quad_cksum`, `DES_string_to_key`,
`DES_string_to_2keys`, `DES_fcrypt`, `DES_crypt`, `MDC2_Init`, `MDC2_Update`, `MDC2_Final`,
`MDC2`, `RC2_set_key`, `RC2_encrypt`, `RC2_decrypt`, `RC2_ecb_encrypt`, `RC2_cbc_encrypt`,
`RC2_cfb64_encrypt`, `RC2_ofb64_encrypt`, `BF_set_key`, `BF_encrypt`, `BF_decrypt`,
`BF_ecb_encrypt`, `BF_cbc_encrypt`, `BF_cfb64_encrypt`, `BF_ofb64_encrypt`, `BF_options`,
`CAST_set_key`, `CAST_encrypt`, `CAST_decrypt`, `CAST_ecb_encrypt`, `CAST_cbc_encrypt`,
`CAST_cfb64_encrypt`, `CAST_ofb64_encrypt`, `IDEA_set_encrypt_key`, `IDEA_set_decrypt_key`,
`IDEA_encrypt`, `IDEA_ecb_encrypt`, `IDEA_cbc_encrypt`, `IDEA_cfb64_encrypt`,
`IDEA_ofb64_encrypt`, `IDEA_options`, `SEED_set_key`, `SEED_encrypt`, `SEED_decrypt`,
`SEED_ecb_encrypt`, `SEED_cbc_encrypt`, `SEED_cfb128_encrypt`, `SEED_ofb128_encrypt`,
`Camellia_set_key`, `Camellia_encrypt`, `Camellia_decrypt`, `Camellia_ecb_encrypt`,
`Camellia_cbc_encrypt`, `Camellia_cfb128_encrypt`, `Camellia_cfb1_encrypt`,
`Camellia_cfb8_encrypt`, `Camellia_ofb128_encrypt`, `Camellia_ctr128_encrypt`,
`CRYPTO_128_wrap`, `CRYPTO_128_unwrap`, `CRYPTO_128_wrap_pad`, `CRYPTO_128_unwrap_pad`,
`CRYPTO_gcm128_new`, `CRYPTO_gcm128_init`, `CRYPTO_gcm128_setiv`, `CRYPTO_gcm128_aad`,
`CRYPTO_gcm128_encrypt`, `CRYPTO_gcm128_decrypt`, `CRYPTO_gcm128_encrypt_ctr32`,
`CRYPTO_gcm128_decrypt_ctr32`, `CRYPTO_gcm128_finish`, `CRYPTO_gcm128_tag`,
`CRYPTO_gcm128_release`, `CRYPTO_ccm128_init`, `CRYPTO_ccm128_setiv`, `CRYPTO_ccm128_aad`,
`CRYPTO_ccm128_encrypt`, `CRYPTO_ccm128_decrypt`, `CRYPTO_ccm128_encrypt_ccm64`,
`CRYPTO_ccm128_decrypt_ccm64`, `CRYPTO_ccm128_tag`, `CRYPTO_xts128_encrypt`,
`CRYPTO_ocb128_new`, `CRYPTO_ocb128_init`, `CRYPTO_ocb128_copy_ctx`, `CRYPTO_ocb128_setiv`,
`CRYPTO_ocb128_aad`, `CRYPTO_ocb128_encrypt`, `CRYPTO_ocb128_decrypt`, `CRYPTO_ocb128_finish`,
`CRYPTO_ocb128_tag`, `CRYPTO_ocb128_cleanup`.

**Open exports (checked against the ledger):** `RSA_new`.
Phase 8.2's cipher families and 8.3's `modes.h` constructions all have their low-level exports in,
and the default provider's AEAD half is nearly there: the twelve AES
key-wrap rows landed in D230, the six CBC-CTS rows in D231, the two AES-XTS rows in D232, the
three AES-OCB rows in D233, the three AES-CCM rows in D238, and the three AES-SIV rows in D241,
on top of the CMAC row and `crypto/modes/siv128.c` that discharged D239's prerequisite — leaving
ChaCha20 and eight of the nine MAC rows open; the AES-GCM rows are
a recorded Phase 9 hand-off rather than open work, because both its no-IV encrypting arm
(`ciphercommon_gcm.c.in:423`) and its TLS arm (`:536`) call RAND_bytes_ex, which `rand.h` owns
(D234) — and then 8.4's RSA object, whose constructor is `RSA_new`.

### The sixteen recorded hand-offs, and why the four key types are not hand-offs

Sixteen of the 786 rows are deferred to Phase 9 by `forensics/phase8-obligations.py`'s
`BLOCKED_HANDOFFS`, and each names the callee, the file and line:

| header | the row | why |
|---|---|---|
| `des.h` | `DES_random_key` | `crypto/des/rand_key.c:22` is `RAND_priv_bytes`, `rand.h` is Phase 9's |
| `rsa.h` | `RSA_blinding_on`, `RSA_setup_blinding` | `RSA_setup_blinding` (`crypto/rsa/rsa_crpt.c:104`) ends in `BN_BLINDING_create_param` → `BN_rand_range_ex` → `RAND_bytes_ex` (`crypto/bn/bn_rand.c:50`) |
| `rsa.h` | `RSA_generate_key`, `_ex`, `RSA_generate_multi_prime_key`, `RSA_X931_generate_key_ex`, `RSA_X931_derive_ex` | `BN_generate_prime_ex2` (`crypto/rsa/rsa_gen.c:388`) |
| `dh.h` | `DH_generate_key`, `DH_generate_parameters`, `_ex`, `DH_KDF_X9_42` | `BN_priv_rand_ex` (`crypto/dh/dh_key.c:336`), `BN_generate_prime_ex2` (`crypto/dh/dh_gen.c:217`), and an `EVP_KDF` fetch of `OSSL_KDF_NAME_X942KDF_ASN1` (`crypto/dh/dh_kdf.c:40`) |
| `dsa.h` | `DSA_generate_key`, `DSA_generate_parameters_ex` | the same two BN paths, `crypto/dsa/dsa_key.c` and `crypto/dsa/dsa_gen.c` |
| `ec.h` | `EC_KEY_generate_key`, `ECDH_KDF_X9_62` | `BN_rand_range` on the group order, and an `EVP_KDF` fetch of `OSSL_KDF_NAME_X963KDF` (`crypto/ec/ecdh_kdf.c:34`) |

**The four key types themselves are not hand-offs, and the reason is worth stating because
the opposite reading is the tempting one.** `RSA_get0_key` needs the `RSA` object that
`RSA_new` allocates; `DH_get0_pqg` needs the `DH` object; `EC_POINT_mul` needs the
`EC_GROUP`. Those are *this stratum's own* work and the ledger records them as `open`,
because a stratum cannot hand a symbol to itself. What is in the table is the subset whose
binding dependency is genuinely another stratum's, verified call by call. The one row whose
phase number is an inference rather than a reading is the two X9 KDF wrappers: the provider
KDF family is not named by any plan yet, so "Phase 9" is where the plan-of-record puts it
and D197 says the row is the one to correct if a later plan says otherwise.

## 3. What each subphase must honour — authority facts already established

Recorded so they are not re-derived per subphase.

1. **Assembly is enabled, and this stratum's exported symbols mostly are not assembly.**
   `configdata.pm`'s `%disabled` does not contain `asm`, `"asm_arch" => "x86_64"` and
   `"perlasm_scheme" => "elf"` are recorded, and the build tree holds both
   `crypto/ec/asm/ecp_nistz256-x86_64.s` and its object. §0's measurement is the
   consequence: nine of this stratum's exports are perlasm's in the authority
   (`AES_cbc_encrypt`, `AES_decrypt`, `AES_encrypt`, `AES_set_decrypt_key`,
   `AES_set_encrypt_key`, `RC4`, `RC4_options`, `RC4_set_key`, `Camellia_cbc_encrypt`) and
   none of the digests' are. **A portable arm is a legitimate reconstruction of a perlasm
   implementation only when a differential court says so**, and §2's two-plane subsection
   amends the reading that used to follow from this: `RT-DIGEST` is the court that proves the
   portable arm is *this* implementation's observable behaviour, and `CT-DIGEST` is the
   *separate* court that proves the construction satisfies the published vectors. The
   differential court is not replaced by vectors, and vectors are not replaced by the
   differential court: a published vector proves the construction is *some* correct
   implementation, and the court proves it is *this* implementation's observable behaviour,
   which is why a primitive-bearing row carries both.
2. **`OPENSSL_NO_DEPRECATED` is not defined.** `configdata.pm`'s `%disabled` does not
   contain `deprecated`, so every `OSSL_DEPRECATEDIN_3_0` declaration in `md4.h`, `md5.h`,
   `sha.h`, `ripemd.h`, `whrlpool.h`, `mdc2.h`, `rsa.h`, `dh.h`, `dsa.h` and `ec.h` is
   compiled and is an obligation. The same fact is why Phase 7's `e_old.c` and its legacy
   wrappers are live.
3. **`OPENSSL_NO_MD4`, `NO_MD5`, `NO_RMD160`, `NO_WHIRLPOOL`, `NO_MDC2`, `NO_SHA3` and
   `NO_SM3` are all absent from the profile**, so those constructions are in the build
   rather than compiled out. `configdata.pm`'s disable list contains `md2`, `rc5`, `mdc2`'s
   neighbour `rc5` and thirty-odd others; **none of the digest or cipher families this
   stratum owns is among them**, which is what the header inventory in §1 already showed
   from the other side: `md2.h` and `rc5.h` are in no atlas row for Phase 8 while
   `mdc2.h` is.
4. **The default provider's algorithm table is `providers/defltprov.c`'s, and the four
   `*_prov.c` files this stratum needs are generated.** `digestcommon.c`, `sha3_prov.c` and
   `blake2_prov.c` are `.c.in` templates the build expands into
   `forensics/authorities/build/openssl-3.6.4-production/providers/implementations/digests/`;
   the others (`md4_prov.c`, `md5_prov.c`, `mdc2_prov.c`, `ripemd_prov.c`, `sha2_prov.c`,
   `sm3_prov.c`, `wp_prov.c`) are plain sources. A reader looking for `sha1_prov.c` will not
   find one: `sha2_prov.c` holds SHA-1, SHA-2 and the two truncated SHA-512 spellings.
5. **BLAKE2 is not in this stratum, and the provider half must say what it does without
   it.** `crypto/blake2/` and `crypto/evp/legacy_blake2.c` were handed to Phase 13 by Phase
   7's 7.3g, and `defltprov.c`'s `deflt_digests[]` carries `ossl_blake2s256_functions` and
   `ossl_blake2b512_functions` between the SHAKE rows and the MDC2 row. The digest half of
   `ossl_default_provider_init` therefore publishes a table with two rows it cannot answer,
   and how that is recorded is a decision 8.1b makes rather than a gap it hides.
6. **`RAND` is Phase 9's and the four key types' *generators* are what need it.** Every
   `*_generate_key`, `*_generate_parameters_ex`, blinding setup and X9 KDF wrapper in §2's
   hand-off table is blocked on it; nothing else in the four key types' arithmetic is, which
   is why 8.4-8.7 can land without Phase 9 at all.
7. **Tracing is compiled out.** `configdata.pm` records `no-trace`, so `OSSL_TRACE` and its
   family expand to nothing and are not a dependency. Phase 6 established this for
   `provider_core.c` and it holds for `crypto/modes/`, `crypto/rsa/` and the rest.

## 4. Constitutional gates this stratum must satisfy

1. **Every export is implemented or handed on with the dependency named.** The ledger is the
   arithmetic; `ownership_audit.py` is the cross-check, and for this stratum it must read the
   Phase 7 → 8 edge in both directions.
2. **Every implemented export is observed by a differential court, and every primitive's
   construction by a correctness court.** The differential half: each probe is compiled twice
   and diffed on `key=value`, and for a primitive whose authority implementation is perlasm,
   it is the *only* evidence that the portable arm is the same observable function — §3's
   first row says why a published test vector cannot stand in for it. The correctness half:
   every primitive-bearing subphase's construction is run against committed vectors whose
   provenance is recorded per vector, and a single mismatch fails the court loudly. Neither
   substitutes for the other — an `RT-*` pass is not independent cryptographic correctness and
   a `CT-*` pass is not OpenSSL parity, nor formal validation — and the two are stated
   separately wherever a verdict is reported (§2's two-plane subsection, D201).
3. **No authority fault is reproduced.** Where a construction dereferences a NULL or relies
   on an uninitialised field — `MDC2_Update`'s `c->num` past `MDC2_BLOCK`,
   `WHIRLPOOL_BitUpdate`'s bit offset — the court does not call it and
   `docs/SECURITY_DIVERGENCE_POLICY.md` records the divergence.
4. **`ABI-PROTOTYPE` covers every declaration**, including the context structs
   `md5.h`/`sha.h`/`whrlpool.h` publish: `MD5_CTX`, `SHA_CTX`, `SHA256_CTX`, `SHA512_CTX`,
   `RIPEMD160_CTX`, `MDC2_CTX` and `WHIRLPOOL_CTX` are all by-value parameters of an
   exported function, so their layouts are part of the contract and `abi-layout.json` is
   what says so.
5. **`ABI-SYMBOL` and `ABI-DYNAMIC` stay clean** for the new surface, which means the
   `libcrypto.so.3` build must keep its `DT_NEEDED`, symbol types, bindings and versions.
   The digest family's version is `OPENSSL_3.0.0` (`symbols-libcrypto.json`'s `num` block) —
   the same node as Phase 7's, so a new `OPENSSL_3.0.0` symbol must not move an existing
   node's ordinal.
6. **The prerequisite gate and the plan reconciliation stay at zero findings.** For a
   stratum still `in-progress` both tools publish their unreached names as a *census* rather
   than a finding, which is what lets 8.0 land a plan that names nine subphases' worth of
   units before any of them exists.
7. **A commit may not undo an earlier commit's evidence**, and the version is an input to
   generated evidence — `docs/RELEASE_GATES.md` §8.

## 5. Process

One staging branch, `phase8-digests`, merged to `main` with `--no-ff` when the stratum is
complete and CI-green, and deleted afterwards. Work is pushed to the staging branch
frequently so that a long stratum survives any single session, and the branch is only merged
when its own seal exists and its ledger reads zero open. Nothing is pushed to `main`, which
is protected, and the branch name is the one 8.0 was created under rather than a name that
matches the later subphases: a branch is a place work lands, and renaming it as the plan
grew would lose the history the plan's own corrections are recorded against.
