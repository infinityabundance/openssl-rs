# Safe-33 closure inventory — `integrate/safe-c33`

> **Superseded (2026-10-22; pointers updated 2026-10-28).** This is a frozen inventory at
> `67ae7f8e9` with crate 0.0.27 and the then-current 8-at-L7 split. It is retained as the
> freeze record and is not the current status. Read
> `forensics/memory-safety/campaign/safe-c33/STATUS-2026-10-20.md`: the current
> atlas records 33/33 cohort families at `L7-functional`, six mechanisms are
> `SAFETY_DISCHARGED` (RC-1, OB-1, OB-2, OB-3, ERR-1, GEN-1), and `Cargo.toml` is
> 0.0.43 (the candidate; 0.0.42 published 2026-10-27). `SAFE_COMPATIBLE` is **0/33**
> because the closure's reachable bound is not monotone
> (`atlas-refresh/closure-monotonicity-finding.json`, **OPEN BLOCKING**), so no
> obligation count from any candidate is carriable. Every figure below remains true of
> the frozen inputs it cites.

Task: `SAFE-C33-001` · branch `integrate/safe-c33` @ `67ae7f8e9` · base `origin/main`
Candidate: `openssl-rs 0.0.27` reconstructing `openssl-3.6.4-production`
(`forensics/downstream/p1000-run.json` `candidate_identity.identity_hash = fe1db3e5…`, `source_commit f0789077a`)
This unit is a **freeze and an inventory only**: it converts no code, runs no evidence chain, and
changes no gate. Every association below is read from committed Phase-22/24/25 evidence.

---

## 1. The frozen 33

Population: `forensics/downstream/family-freeze.json` (selection root
`f2a0454f…`, 1,000 direct-OpenSSL families). Verdict source: `forensics/downstream/p1000-run.json`
(`body_hash 84023c90…`), re-derived by `forensics/downstream/reconciliation.json`
(`body_hash 327ab08b…`). The reviewer's size is exact: **33 `DROP_IN_PASS`**, in
**25 at `L4-linked` + 8 at `L7-functional`** (`counts.measurable_families = 33`,
`ladder.levels.L4-linked = 33`, `.L5-loaded = .L6-runtime = .L7-functional = 8`;
`DROP_IN_FAIL = DROP_IN_PARTIAL = DROP_IN_UNKNOWN = 0`, `DROP_IN_NOT_APPLICABLE = 967`).

### 1a. The 8 with functional (L7) evidence

| family | id | rank | surface the runtime observed | libssl | symbol fingerprint |
|---|---|---|---|---|---|
| curl | `family:curl` | 9 | verified TLS1.3 fetch + unrelated-CA reject | yes | `usage-fingerprints` (227 syms) |
| haproxy | `family:haproxy` | 14 | TLS terminator with a verified response | yes | `usage-fingerprints` (338) |
| isync | `family:isync` | 16 | IMAPS fetch from a local IMAP peer into a Maildir | yes | — (none recorded) |
| monit | `family:monit` | 27 | TLS httpd handshake + HTTP response | yes | `usage-fingerprints` (65) |
| nginx | `family:nginx` | 88 | verified TLS1.3 server response | yes | — (none recorded) |
| openssh | `family:openssh` | 34 | ssh-keygen Ed25519 sign/verify (libcrypto) | no | `usage-fingerprints` (179) |
| pure-ftpd | `family:pure-ftpd` | 39 | authenticated FTPS login + PWD (explicit TLS) | yes | `usage-fingerprints` (43) |
| redis | `family:redis` | 40 | TLS handshake + encrypted PING/+PONG | yes | `usage-fingerprints` (51) |

### 1b. The 25 with only build/link (L4) evidence

`cyrus-sasl, dovecot, fetchmail, fossil, hiredis-ssl, iperf3, keepalived, kmod, ldns, libarchive,
libevent, librdkafka, libretls, links, mosquitto, openvpn, proxytunnel, rsync, socat, squid,
sslscan, ssmtp, stunnel, tinc, tnftp` — all `L4-linked`, `residual=none`, `patch_count=0`,
`imported_openssl_symbols_count` 5–298 (`p1000-run` run rows). Seven of these link **libcrypto
only** (`cyrus-sasl, iperf3, kmod, ldns, libarchive, rsync, tinc`) and so cannot need the
SSL/SSL_CTX/session boundary; the rest link libssl (from `dt_needed`).

**Symbol-level evidence covers 6 of 33 only.** Full `imported_openssl_symbols` lists exist
solely in `forensics/downstream/usage-fingerprints.json` (6 fingerprinted families). For the other
27, only the import **count** and the runtime `surface_used` are recorded. `isync` and `nginx`
reach L7 yet carry no fingerprint (`phase24-crosswalk` finding: "2 runtime-observed families
without a fingerprint cannot be attributed to a site").

---

## 2. Mechanism table

**State vocabulary** (defined here; an unproven raw-pointer boundary is **never** `SAFETY_DISCHARGED`
merely because a `Drop` wrapper exists):

- **UNSAFE_OPEN** — no ownership work on the mechanism's raw boundary on this branch; boundary open.
- **OWNERSHIP_RECONSTRUCTED** — the branch models ownership for (some of) the region with owning
  types / `Drop`, but no proof discharges the raw-pointer boundary.
- **SAFETY_DISCHARGED** — a per-site safety contract for the boundary is proven (no unexplained
  reachable site in the mechanism). Not claimed from a `Drop` wrapper alone; **no mechanism is here**.
- **COMPATIBILITY_CONFIRMED** — downstream drop-in build/link (L4) confirmed against the authority.
- **SAFE_COMPATIBLE** — the mechanism is `SAFETY_DISCHARGED` **and** a functional (L7) result is
  confirmed for families depending on it. **None**.
- **BLOCKED** — cannot advance (no authority unit / external dependency). **None**.

Family / volume columns: `meas` = families proven to depend by symbol fingerprint; `infer` =
families inferred from linkage (`libssl`/`libcrypto`) + runtime surface. `ops` = compiler-derived
crate `unsafe_operations` over the mechanism's subsystems (`artifacts/phase25/source-census.json`,
172,091 total). `conv` = `src/` files this branch already converted.

| mechanism (category) | families (meas+infer) | ops | conv | state | authority evidence |
|---|---|---|---|---|---|
| **ERR** (BIO/error) | 33 (6+27) | 540 | 0 | UNSAFE_OPEN | `crypto/err` |
| **RAND_CMS_STORE_KEYFMT** (RAND/CMS/STORE/key formats) | 33 (6+27) | 21,499 | 3 | OWNERSHIP_RECONSTRUCTED | `crypto/rand,cms,store,pem,pkcs7,pkcs12` |
| **BIO** (BIO/error) | 32 (5+27) | 6,593 | 0 | UNSAFE_OPEN | `crypto/bio` |
| **EVP_PKEY_PROVIDER** (EVP/PKEY/digest/cipher/provider state) | 32 (5+27) | 90,830 | 11 | OWNERSHIP_RECONSTRUCTED | `crypto/evp,providers,ec,rsa,bn,…` |
| **ASN1_OCSP** (X.509/ASN.1) | 31 (4+27) | 10,865 | 0 | UNSAFE_OPEN | `crypto/asn1,ocsp,ts,objects` |
| **RUNTIME_ALLOC_OWNERSHIP** (runtime allocator/ownership) | 31 (4+27) | 4,229 | 0 | UNSAFE_OPEN | `crypto/mem,stack,ex_data,init` |
| **X509_VERIFY_POLICY** (X.509 verify/policy) | 31 (4+27) | 18,207 | 6 | OWNERSHIP_RECONSTRUCTED | `crypto/x509` |
| **RUNTIME_CONCURRENCY** (runtime concurrency) | 25 (5+20) | 1,572 | 2 | OWNERSHIP_RECONSTRUCTED | `crypto/threads,init` |
| **SSL_SESSION** (SSL/SSL_CTX/session) | 25 (5+20) | 11,781 | 4 | OWNERSHIP_RECONSTRUCTED | `ssl/` |

**Headline.** Across the cohort: `COMPATIBILITY_CONFIRMED` for all 33 (25 build/link, 8 also
functional). **0 mechanisms are `SAFETY_DISCHARGED`; 0 families are `SAFE_COMPATIBLE`.** Four
mechanisms are `UNSAFE_OPEN` (ERR, BIO, ASN1_OCSP, RUNTIME_ALLOC_OWNERSHIP); five are
`OWNERSHIP_RECONSTRUCTED` (a `Drop`/owning-type reconstruction with no discharge proof). The
Phase-25 ownership plane (`artifacts/phase25/ownership-planes.json`) is why the reconstructed
mechanisms are not discharged: it records, structurally, **187 unmatched `FREES`**, **368 unmatched
refcount decrements**, **35 double-free contexts**, **25 unsynchronized mutable globals with no
source contract**, and **5,080 exported C-ABI functions whose unwind class is UNKNOWN** — each a
possibility the structure admits, never asserted as a defect. The Phase-25 seal agrees:
`artifacts/phase25/summary.json` records `passed=false`, 183 externally reachable UNSUPPORTED sites,
449 open residuals, `parity_status=WITHHELD`.

Distinct plane (candidate-level): `artifacts/phase25/mechanisms.json` reconciles the **7 memory-safety
CVE *mechanisms*** — 3 `ELIMINATED`, 3 `HIDDEN` (CMS, CMS, X.509 — operation kind survives inside the
abstraction), 1 `UNRESOLVED` (`ssl/dtls`, no resolved region). This is not the ownership-mechanism
table above and is never summed with it.

---

## 3. Leverage ranking and worklist

Ranking rule: **primary** = families of the 33 that depend (upper bound on families a discharge would
unblock); **tie-break** = fewer already-converted files (more open) then smaller `ops` (cheaper).
Leverage is toward the **safe** claim, not the drop-in claim — all 33 already reach L4.

| # | mechanism | families unlocked | state | already on branch | next action |
|---|---|---|---|---|---|
| 1 | ERR | 33 | UNSAFE_OPEN | no | audit `crypto/err` sites in `src/runtime/err*` + `ssl_err_legacy`; model the error-queue/`ERR_STATE` ownership; prove per-site contract |
| 2 | RAND_CMS_STORE_KEYFMT | 33 | OWNERSHIP_RECONSTRUCTED | `provider/rand.rs`, `cms/cms_env.rs`, `pem/pvkfmt.rs`, `store/store_lib.rs` | discharge DRBG/CMS/STORE/`pkcs7`/`pkcs12` boundaries; RAND+PEM are near-universal, so a sub-split (DRBG vs key formats) is warranted |
| 3 | BIO | 32 | UNSAFE_OPEN | no | audit `crypto/bio` (`src/runtime/bio`, `core_bio`, `bio_ssl`, method/ctrl callbacks); BIO method-table ownership |
| 4 | EVP_PKEY_PROVIDER | 32 | OWNERSHIP_RECONSTRUCTED | 11 files (`evp/{digest,e_aes,p_legacy,pkey_ctx}`, `provider/{cipher,digest,kdf,mac,rand}`, `ec/smpl`, `hpke`) | largest volume (90.8k ops); carry the reconstruction to discharge on `evp`/`provider` contexts and the key primitives |
| 5 | RUNTIME_ALLOC_OWNERSHIP | 31 | UNSAFE_OPEN | no | `src/runtime/mem*`, `secure`, `ex_data`, `stack`, `lhash`; the foundational boundary every other mechanism rests on — hook observability is behaviour (`sparse-array-differential.json`) |
| 6 | ASN1_OCSP | 31 | UNSAFE_OPEN | no | `src/asn1`,`ocsp`,`ts`,`runtime/obj`; the `d2i_*`/`i2d_*` depth/length contracts |
| 7 | X509_VERIFY_POLICY | 31 | OWNERSHIP_RECONSTRUCTED | `x509/pcy_{data,node,tree,lib}.rs`, `x509/v3_utl.rs`, `x509/x509_vfy.rs` + the policy differential court | strongest sub-evidence (model `campaign/x509-policy-tree`); finish verify/store; the `TRANSMUTE` at `vm-type-confusion-crypto-x509` is still `HIDDEN` |
| 8 | RUNTIME_CONCURRENCY | 25 | OWNERSHIP_RECONSTRUCTED | `runtime/thread_events.rs`, `context/namemap.rs` (the `fix(p25)` default-libctx namemap synchronisation) | finish `crypto/threads`/init; 25 unsynchronized mutable globals remain |
| — | SSL_SESSION | 25 | OWNERSHIP_RECONSTRUCTED | `ssl/ssl_lib.rs`, `ssl/ssl_sess.rs`, `ssl/statem/{statem_clnt,statem_srvr}.rs` | (rank 9) finish SSL/CTX/cert/session + remaining `statem`; `ssl/dtls` is the `UNRESOLVED` CVE mechanism |

Remaining 967: dependence is **unknown** — all 967 are `DROP_IN_NOT_APPLICABLE` for want of an
admitted source recipe, so no mechanism can be attributed to them. The growth path is the recipe
queue (`shared-blockers.recipe_queue`, **40 named families**: jwt, cargo, alpine, borgbackup, clamav,
grpc, mariadb, nmap, nsd, tor, unbound, znc, …); their linkage (`libssl` vs `libcrypto`) is the only
first-order signal available before a recipe is admitted.

---

## 4. Non-claims

1. **Candidate-level crosswalk, not execution.** `artifacts/phase25/phase24-crosswalk.json` maps a
   consumer to a site when the consumer's **ELF symbol table** names a symbol the site's unit
   provides — an *import* observation, never an execution (`mapping_rule`, `import_observation`).
   44,872 sites are `DOWNSTREAM_RUNTIME_OBSERVED`, 0 `DOWNSTREAM_IMPORT_OBSERVED`; a functional run
   attests the workload ran, not that it entered any site.
2. **The join speaks for 6 of 1,000.** Only the fingerprinted families carry symbol-level evidence,
   so mechanism dependence is *measured* for 6 and *inferred from linkage/surface* for 27; the
   inferred rows are labelled `linkage-inferred` and are not evidence of a site.
3. **Reconstruction is not discharge.** A `Drop` wrapper or owning type is recorded as
   `OWNERSHIP_RECONSTRUCTED`; it is never `SAFETY_DISCHARGED`. The ownership plane's structural
   findings (unmatched frees/refcounts, double-free contexts, unsynchronized globals, UNKNOWN unwind
   classes) all remain open.
4. **Leverage is an upper bound.** The family counts are dependence counts, not a minimal hitting
   set; the true "families unlocked by converting M" needs per-mechanism per-family discharge, which
   the evidence does not carry.
5. **A pass is not a proof.** 33/33 is a selected population, not a random sample; a build is not a
   functional proof; `NOT_APPLICABLE` is not a pass. The bounded Phase-25 claim is stated, not proven
   (`passed=false`), and the parity claim is withheld.
6. **The CVE-mechanism plane is separate.** The 7 reconciled CVE mechanisms (3 eliminated / 3 hidden
   / 1 unresolved) are candidate-level CVE dispositions, never summed with the ownership mechanisms.

## 5. Pointers
- machine state: `forensics/memory-safety/campaign/safe-c33/state.json`
- cohort: `forensics/downstream/{p1000-run,family-freeze,reconciliation,runtime-functional-atlas,usage-fingerprints}.json`
- mechanisms: `artifacts/phase25/{source-census,ownership-planes,mechanisms,phase22-crosswalk,phase24-crosswalk,summary}.json`
- sibling campaign: `forensics/memory-safety/campaign/x509-policy-tree/` (rank-7 evidence)
