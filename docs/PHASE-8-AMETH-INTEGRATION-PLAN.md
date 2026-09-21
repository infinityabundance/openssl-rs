# Integration plan — Phase 8.8's ASN.1 method objects and `standard_methods[]`

This document is the plan for **the fifteen labels `forensics/phase8-obligations.json` assigns to
`src/asn1/ameth.rs`** and for the `crypto/asn1/ameth_lib.c` table they exist to populate: the
`standard_methods[]` array of `crypto/asn1/standard_methods.h`, its rows, and the
`ossl_<alg>_asn1_meth` objects the rows point at.

It is a plan, not a landing: **nothing under `src/`, `courts/`, `forensics/` or `docs/` is touched by
this file**, and the plan itself is not part of the build. It exists because the measurement in §3
says the subphase cannot be cut to a compiling boundary at this stratum's frontier, and a plan that
records *why* is worth more than an attempt that fabricates a method table.

It is written against what the crate *already* has, read rather than assumed:

* `src/evp/pkey_asn1.rs` (1,095 lines) already holds **all twenty-six of `ameth_lib.c`'s exports** —
  the eight accessors, the fifteen `EVP_PKEY_asn1_set_*` mutators, the two `find` functions and
  `get0_asn1` (Phase 7.4c-ii). Its `STANDARD_METHODS` is `[*const EvpPkeyAsn1Method; 0]` and
  `pkey_asn1_find` searches it, so `EVP_PKEY_asn1_find`/`_find_str` answer NULL for every standard
  type — the `D-PKEY-AMETH-1` divergence, which is the *only* thing 8.8 changes about this file.
* `EvpPkeyAsn1Method` is declared at `pkey_asn1.rs:145` with the authority's forty-one members in ABI
  order. The four struct types the callbacks take — `X509Pubkey` (`:116`), `Pkcs8PrivKeyInfo` (`:121`),
  `X509Algor` (`:126`) and `X509SigInfo` (`:131`) — are `#[repr(C)]` with `_private: [u8; 0]` and the
  comment "**Phase 10's object**" (the atlas resolves `X509_PUBKEY_*`, `X509_ALGOR_*` and
  `PKCS8_pkey_*` to **Phase 11**, which is the coordinate §5 uses).
* `src/evp/pkey.rs` is `crypto/evp/p_lib.c` and `src/evp/pkey_ctx.rs` is `pmeth_lib.c`; both are
  landed. `src/asn1/x_bignum.rs`, `x_int64.rs` and `x_long.rs` are landed, so the three `x_*.c`
  units this brief names are already in.
* The gate's own universes, read from `forensics/atlas/prerequisite-gate.json`: **307** crate modules
  over **235** authority units, **52** sealed-census names and **20** blocking dependencies, zero
  findings. Two of the twenty are 8.8's and name it exactly: `ossl_rsa_asn1_meths` and
  `ossl_rsa_pkey_method`.

---

## 1. What 8.8 is, counted from the authority rather than from the row

The row says "twelve objects". The authority's table holds **fifteen rows over eleven named
objects**, and the difference is not a rounding: `crypto/asn1/standard_methods.h` is compiled under
this profile's guards, and `OPENSSL_NO_ECX`, `OPENSSL_NO_SM2`, `OPENSSL_NO_DH`, `OPENSSL_NO_DSA` and
`OPENSSL_NO_EC` are all absent from the admitted `configuration.h` (§5 records the count as a
disagreement rather than smoothing it over).

```text
&ossl_rsa_asn1_meths[0]      crypto/rsa/rsa_ameth.c    NID_rsaEncryption
&ossl_rsa_asn1_meths[1]      crypto/rsa/rsa_ameth.c    NID_rsa  (ASN1_PKEY_ALIAS)
&ossl_dh_asn1_meth           crypto/dh/dh_ameth.c     NID_dhKeyAgreement
&ossl_dsa_asn1_meths[0..3]   crypto/dsa/dsa_ameth.c   NID_dsa, NID_dsaWithSHA, ... (two aliases)
&ossl_eckey_asn1_meth        crypto/ec/ec_ameth.c     NID_X9_62_id_ecPublicKey
&ossl_rsa_pss_asn1_meth      crypto/rsa/rsa_ameth.c    NID_rsassaPss
&ossl_dhx_asn1_meth          crypto/dh/dh_ameth.c     NID_dhpublicnumber
&ossl_ecx25519_asn1_meth     crypto/ec/ecx_meth.c     NID_X25519
&ossl_ecx448_asn1_meth       crypto/ec/ecx_meth.c     NID_X448
&ossl_ed25519_asn1_meth      crypto/ec/ecx_meth.c     NID_ED25519
&ossl_ed448_asn1_meth        crypto/ec/ecx_meth.c     NID_ED448
&ossl_sm2_asn1_meth          crypto/ec/ec_ameth.c     NID_sm2
```

`OBJ_bsearch_ameth` requires the array ascending by `pkey_id` and complete: a table that omits any
row cannot answer for the types above it, and one that carries a row whose callback field is not the
authority's is a fabricated method, not a smaller landing. **The four ECX rows and the SM2 row are
this table's and not the four `*_ameth.c` files the brief names**, and `crypto/ec/ecx_meth.c` (1,468
lines, fifty-five functions, four rows) has **no crate module and no stratum's plan row** — D316
records its provider half as Phase 8's, but no obligation row names the ASN.1 object's unit.

## 2. Every unit the table and the fifteen labels reach

| unit | authority | 8.8's export | crate module |
|---|---|---|---|
| `crypto/asn1/ameth_lib.c` | 438 lines | the table (no export) | `src/evp/pkey_asn1.rs` (landed) |
| `crypto/rsa/rsa_ameth.c` | 1,053 lines, 36 fns | `ossl_rsa_asn1_meths[2]`, `ossl_rsa_pss_asn1_meth` | `src/rsa/ameth.rs` (new) |
| `crypto/dh/dh_ameth.c` | 648 lines, 33 fns | `ossl_dh_asn1_meth`, `ossl_dhx_asn1_meth` | `src/dh/ameth.rs` (new) |
| `crypto/dsa/dsa_ameth.c` | 579 lines, 26 fns | `ossl_dsa_asn1_meths[4]` | `src/dsa/ameth.rs` (new) |
| `crypto/ec/ec_ameth.c` | 720 lines, 31 fns | `ossl_eckey_asn1_meth`, `ossl_sm2_asn1_meth` | `src/ec/ameth.rs` (new) |
| `crypto/ec/ecx_meth.c` | 1,468 lines, 55 fns | `ossl_ecx{25519,448}_asn1_meth`, `ossl_ed{25519,448}_asn1_meth` | `src/ec/ecx_meth.rs` (new, unowned) |
| `crypto/asn1/d2i_pu.c` | 98 lines | `d2i_PublicKey` | `src/asn1/ameth.rs` (new) |
| `crypto/asn1/d2i_param.c` | 64 lines | `d2i_KeyParams`, `d2i_KeyParams_bio` | `src/asn1/ameth.rs` (new) |
| `crypto/evp/evp_pkey_type.c` | 88 lines | `EVP_PKEY_type` | `src/asn1/ameth.rs` (new) |
| `crypto/evp/p_lib.c` (part) | `:791` `EVP_PKEY_assign`, four accessors | five of the fifteen | `src/asn1/ameth.rs` |
| `crypto/evp/pmeth_lib.c` (part) | `:106`, `:646`, `:655` | `EVP_PKEY_meth_find`/`_get0`/`_get_count` | `src/asn1/ameth.rs` |

`crypto/asn1/d2i_pr.c` (258) and `i2d_evp.c` (169) are **not** on this closure: no `*_ameth.c`
callback calls `d2i_PrivateKey*` or `i2d_PublicKey*`. They are listed in the brief as reachable and
they are not — the two units a decoder/encoder context blocks are `d2i_pr.c`'s
`d2i_PrivateKey_decoder` and `i2d_evp.c`'s `i2d_provided`, and those are Phase 7's exports already
withheld on Phase 10 (`forensics/prerequisites.json` carries both coordinates). §5 records it.

## 3. The closure, measured, and the finding that shapes the whole subphase

The lexical closure below was measured by scanning each unit for the identifiers that resolve to
`forensics/atlas/symbol-ownership.json` records owned by a stratum other than 8, then reading each
hitting function's body for the Phase 10 and Phase 11 names. It is the same scan the gate's
direction A performs, at file granularity rather than name granularity.

**Every one of the five object-bearing units has callbacks that reach Phase 11, and they are the
methods the table needs by name.**

| unit | functions touching Phase 10/11 | names | coordinate |
|---|---|---|---|
| `rsa_ameth.c` | 7 of 36 | `X509_PUBKEY_set0_param` `:67`; `X509_PUBKEY_get0_param` `:83`; `PKCS8_pkey_set0` `:162`; `X509_ALGOR_free` `:295`; `X509_signature_dump` `:416`; `X509_ALGOR_set0` `:680`, `:687` and `d2i_X509_ALGOR` `:707`, `:713`; `X509_SIG_INFO_set` `:771` | `X509_PUBKEY_*`/`X509_ALGOR_*`/`PKCS8_pkey_*` are `x509.h`, **Phase 11**; `d2i_X509_ALGOR` is `crypto/asn1/x_algor.c`, **Phase 11** |
| `dh_ameth.c` | 3 of 33 | `X509_PUBKEY_get0_param` `:72` and `X509_ALGOR_get0` `:74`; `X509_PUBKEY_set0_param` `:147`; `PKCS8_pkey_set0` `:215` | Phase 11 |
| `dsa_ameth.c` | 4 of 26 | `X509_PUBKEY_get0_param` `:41` and `X509_ALGOR_get0` `:43`; `X509_PUBKEY_set0_param` `:134`; `PKCS8_pkey_set0` `:205`; `X509_signature_dump` `:408` | Phase 11 |
| `ec_ameth.c` | 3 of 31 | `X509_PUBKEY_set0_param` `:90`; `X509_PUBKEY_get0_param` `:110`; `PKCS8_pkey_set0` `:190` | Phase 11 |
| `ecx_meth.c` | 7 of 55 | `X509_PUBKEY_set0_param` `:45`; `X509_PUBKEY_get0_param` `:62`; `PKCS8_pkey_set0` `:120`; `X509_ALGOR_get0` `:551`; `X509_ALGOR_set0` `:568`, `:570`; `X509_SIG_INFO_set` `:586`, `:602` | Phase 11 |
| `d2i_pu.c` | **none** | — | — |
| `d2i_param.c` | **none** | `BUF_MEM_free`, `asn1_d2i_read_bio` are Phase 4/5, present | — |
| `evp_pkey_type.c` | **none** | `ENGINE_finish` is Phase 13's, and the arm cannot fire (the `pkey_asn1.rs` precedent writes `*pe = NULL` and nothing else) | — |

The other external names the units need are Phase 3 (`OBJ_nid2obj`), Phase 4 (`BIO_*`), Phase 5
(`ASN1_*`, `BN_*`, `i2a_*`) and Phase 7 (`EVP_PKEY_CTX_*`, `EVP_MD_get_type`), all of which are
landed; and Phase 6's `OSSL_PARAM_BLD_*`/`OSSL_PARAM_*`, also landed (`src/params/`).

## 4. Why no boundary compiles, and it is a cycle rather than a preference

The tempting reading is that the table is "just data" and lands first, with the callbacks arriving
after. It cannot, and the reason is the same one D339 measured for EC: a `const
EVP_PKEY_ASN1_METHOD` carries **function pointers**, and a Rust `static` naming a function that does
not exist does not compile.

So the order is forced:

1. `pub_encode`/`pub_decode`/`priv_encode` are table columns, so they must exist before the object
   literal does.
2. Their bodies read `X509_PUBKEY`/`X509_ALGOR`/`PKCS8_PRIV_KEY_INFO` fields, which are
   `_private: [u8; 0]` here because their **bodies are Phase 11's** (`X509_PUBKEY_set0_param`,
   `X509_PUBKEY_get0_param`, `X509_ALGOR_get0`, `X509_ALGOR_set0`, `PKCS8_pkey_set0`,
   `X509_SIG_INFO_set`, `X509_signature_dump`, `d2i_X509_ALGOR`). A transcription that reached
   through the opaque type would be a fabricated layout; one that returned early would be a
   fabricated answer.
3. So the table cannot exist before Phase 11, and the two exports that read it —
   `EVP_PKEY_type` (`evp_pkey_type.c:70`) and `EVP_PKEY_assign` (`p_lib.c:791`, which sets
   `pkey->ameth = EVP_PKEY_asn1_find(NULL, type)`) — cannot exist either.
4. And the twelve key-type accessors that wait on `evp_pkey_get_legacy`
   (`forensics/prerequisites.json`, owner_phase 8) wait on the same registry, because
   `evp_pkey_get_legacy`'s cache is keyed on `ameth` being non-NULL and `evp_pkey_copy_downgraded`
   reads `ameth->import_from` and `ameth->dirty_cnt` directly.

That is the whole of 8.8's acceptance claim — "this is what retires the 27 Phase-8 rows in Phase 7's
`deferred_by_phase`" — and the measurement says it retires them **only together with Phase 11's
`X509_PUBKEY`, `X509_ALGOR` and `PKCS8_PRIV_KEY_INFO` bodies**, which is the boundary the brief's
own rule points at ("if a callee is another stratum's ... stop and name it with its authority
coordinate rather than stubbing").

## 5. The names left unlanded, with their coordinates and stratum

| name | defined in | declared in | stratum |
|---|---|---|---|
| `X509_PUBKEY_set0_param` | `crypto/x509/x_pubkey.c` | `x509.h` | **Phase 11** |
| `X509_PUBKEY_get0_param` | `crypto/x509/x_pubkey.c` | `x509.h` | **Phase 11** |
| `X509_ALGOR_get0` | `crypto/asn1/x_algor.c` | `x509.h` | **Phase 11** |
| `X509_ALGOR_set0` | `crypto/asn1/x_algor.c` | `x509.h` | **Phase 11** |
| `X509_ALGOR_free` | `crypto/asn1/x_algor.c` | `x509.h` | **Phase 11** |
| `d2i_X509_ALGOR` | `crypto/asn1/x_algor.c` | `x509.h` | **Phase 11** |
| `PKCS8_pkey_set0` | `crypto/x509/x_pubkey.c` | `x509.h` | **Phase 11** |
| `PKCS8_pkey_get0` | `crypto/x509/x_pubkey.c` | `x509.h` | **Phase 11** |
| `X509_SIG_INFO_set` | `crypto/x509/x_sig.c` | `x509.h` | **Phase 11** |
| `X509_signature_dump` | `crypto/x509/x_algor.c` | `x509.h` | **Phase 11** |
| `d2i_PrivateKey_decoder`'s `OSSL_DECODER_CTX_*` | `crypto/asn1/d2i_pr.c:29` | `decoder.h` | **Phase 10** |
| `i2d_provided`'s `OSSL_ENCODER_CTX_*` | `crypto/asn1/i2d_evp.c:31` | `encoder.h` | **Phase 10** |
| `crypto/ec/ecx_meth.c` whole | — | no header | **no stratum** — D316 names its provider half 8's but no obligation row names the unit |

The Phase 11 and Phase 10 rows above are the two `blocking_dependencies` rows the gate already
carries for `ASN1_item_sign_ctx` / `ASN1_item_verify_ctx` and for
`OSSL_DECODER_CTX_new_for_pkey` / `OSSL_ENCODER_CTX_new_for_pkey`; the eight `X509_*`/`PKCS8_*`
names are not separately recorded because nothing in the **current** crate references them. They
become `undefined_prerequisite` findings on exactly the commit that first names them, which is why
this plan does not pre-write `forensics/prerequisites.json` rows for them: a divergence record for a
name the gate did not observe is rejected by the gate's own rule ("a divergence record may not cover
a name the gate did not observe").

## 6. What could land without the table, and whose module it is

Three of the ten units in §2 have a closure that is empty of Phase 10/11 names. They are **not**
8.8's labels, and they are not landable *by this subphase* without moving another subphase's rows:

* `crypto/asn1/d2i_pu.c`'s `d2i_PublicKey` needs `d2i_RSAPublicKey`, `d2i_DSAPublicKey` and
  `o2i_ECPublicKey` — `crypto/{rsa,dsa,ec}/*_asn1.c`'s, whose modules are 8.4/8.6/8.7's
  (`src/rsa/mod.rs` carries `d2i_RSAPublicKey` and eleven siblings as `open` today).
* `crypto/dsa/dsa_asn1.c` (72 lines) has **no** non-Phase-8 reference at all; `dh_asn1.c` (167) needs
  only Phase 5; `ec_asn1.c`'s closure is Phase 3/4/5; `rsa_asn1.c` needs `X509_ALGOR_free` for the
  two PSS/OAEP templates but its plain `RSAPublicKey`/`RSAPrivateKey` templates do not.
* `crypto/{rsa,dh,dsa,ec}/*_pmeth.c` and the four `*_ctrl.c` units reach only Phase 6/7, so the
  `ossl_*_pkey_method` half of the gate's second blocking row is closer than the ASN.1 half — but
  `rsa_pmeth.c` calls `EVP_PKEY_get0_RSA`, which is `open`, and `evp_pkey_get_legacy` sits under it.

A landing of the plain key codecs is therefore possible as **8.4's, 8.5's, 8.6's and 8.7's work**, in
their own modules, and this plan records it rather than folding it into 8.8: the ledger assigns those
names to `src/{rsa,dh,dsa,ec}/mod.rs`, and moving them here would move four other rows' modules.

## 7. The court, and why `RT-AMETH` cannot be registered yet

`forensics/tools/phase8_courts.py`'s `COURTS` list is the registry, and its own note says a runner
that names a probe which does not exist cannot be committed. `RT-AMETH` is not registered and
`courts/phase8/rt_ameth_probe.c` does not exist, and registering it now would be wrong in the
direction the runner checks: an arm that called `EVP_PKEY_asn1_find(NULL, EVP_PKEY_RSA)` would print
a real method object from the authority and NULL from the crate, so the court would carry residuals
rather than observations.

The arms it *will* carry, in the order they become observable, are recorded here so the landing
commit writes them rather than inventing them:

1. `EVP_PKEY_asn1_get_count` and `EVP_PKEY_asn1_get0` over the whole table, by index, printing each
   row's `pkey_id`/`pkey_base_id`/`pkey_flags` from `EVP_PKEY_asn1_get0_info` and its `pem_str`.
2. `EVP_PKEY_asn1_find(NULL, type)` for all fifteen `pkey_id`s, printing the same five fields;
   `EVP_PKEY_asn1_find_str(NULL, "RSA", -1)` and the lowercase and wrong-length refusals.
3. `EVP_PKEY_type` for the fifteen ids plus `NID_undef`, which is the alias chain's observable
   (`EVP_PKEY_type(EVP_PKEY_RSA2)` answers `EVP_PKEY_RSA`).
4. `EVP_PKEY_assign` followed by `EVP_PKEY_get0_asn1`, which is the field the assignment sets.
5. The `sizeof`/bits/security-bits callbacks through a key the crate can build, printing the
   verdict and never a key byte; and the `param_missing`/`param_copy`/`param_cmp` trio.
6. Every refusal with its drained `ERR` coordinate, which the probe prints as `reason=` and never
   as a secret; `d2i_KeyParams`'s `ASN1_R_UNSUPPORTED_TYPE` arm is the first of them.

## 8. Falsification tests

* If the table were landable without Phase 11, a `static STANDARD_METHODS` naming the five objects
  would compile with the callbacks withheld — it does not, and §4 step 1 is the reason. A next
  session can check this in minutes by placing any one object literal in an undeclared module and
  running `cargo check`.
* If the count were twelve, `standard_methods.h` would carry twelve rows; it carries fifteen, and
  §1 lists them. The `OSSL_NELEM` the authority's `EVP_PKEY_asn1_get_count` returns is 15 plus the
  application count.
* If `d2i_pu.c` were the withdrawal the `prerequisites.json` row calls it, `d2i_PublicKey` would
  have an ameth call; it assigns `ret->pkey.rsa` directly and never touches `ameth`. The row's
  reason is the *table's* absence, not a call from this unit.

## 9. Bookkeeping

This plan lands nothing. `forensics/phase8-obligations.json` stays `complete: false`, implemented
**612**, deferred **1**, open **173**, owned **786**, with `src/asn1/ameth.rs` still holding all
fifteen; `forensics/prerequisites.json` gains no row (nothing new references a later stratum's
name); the guard moves no `sealed_stratum_census` or `blocking_dependencies` figure, so no
`forensics/ownership-transitions.json` row is needed; and `docs/PHASE-8-SUBPHASES.md`'s two anchored
clauses are untouched because no symbol moved between them.
