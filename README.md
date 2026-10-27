# openssl-rs

A native Rust reimplementation of OpenSSL 3.6.4 targeting source, ABI, and
observable behavioural compatibility.

`openssl-rs` reconstructs the OpenSSL distribution contract — `libcrypto`,
`libssl`, providers, public headers, static libraries, and the `openssl` CLI —
without using OpenSSL or another cryptographic library as its implementation
backend. It is not a wrapper around OpenSSL, `rustls`, AWS-LC, BoringSSL,
LibreSSL, or `ring`.

| | |
|---|---|
| OpenSSL authority | `openssl-3.6.4-production` (3.6.4) |
| Platform | `linux-x86_64` |
| Build profile | `linux-x86_64-default-shared-legacy-notests` |
| Implementation | one first-party Rust crate, zero dependencies |

> **Status:** the implementation state is generated, not typed here. `IMPLEMENTED`
> (a symbol the crate's compiled output defines) and `SCAFFOLDED` (a shell-only
> abort) are counted in [`STATUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/forensics/STATUS.md)
> and [`SEAL-CENSUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/SEAL-CENSUS.md),
> which are authoritative; this page does not restate the counts. `IMPLEMENTED` is
> neither `PARITY_VERIFIED` nor a compatibility claim.

## What is achieved

Measured at the source identity rendered below. The reuse row states how many
measurements are carried forward, and the superseded identity they were measured
at. Every row names its own machine-readable evidence; none of them is a claim
of completeness.

<!-- BEGIN GENERATED: readme-achievements -->
Source identity: crate version `0.0.41` (**published** 2026-10-27, checksum `0d32b709…`); `libcrypto.so.3` sha256 `26ba36ffff2882845fa51d8f29d8239a51c15422629a31c216af8abafa163be0`; `libssl.so.3` sha256 `1e7a9e8f93495dbacdf5dad2f65e355f89248d6ab155704112be444c1abb0a9b`. Derived by `forensics/tools/render_docs.py`; `--check` fails if a block and its evidence disagree.

| Dimension | Result | Evidence |
|---|---|---|
| **Downstream drop-in, Safe-33 cohort** | **33 / 33 families at `L7-functional`**, candidate and authority; **carried forward** — 33/33 cohort rows are in `evidence_reuse.reused_families` and `candidate_identity_match=false` | `forensics/downstream/runtime-functional-atlas.json` (`body.runs`); `CAMPAIGN-STATUS.json` (`consumers`) |
| **Downstream drop-in, 1000-family corpus** | **207 / 1000 at `L7-functional`**; candidate 207 / authority 209 `L7-functional`; measured asymmetry: authority-only `ewftools`, `xilinx-bootgen`; **307 recipes, 253 built, 245 linked**; 223 loaded, 22 `L4-linked`, 7 failed, 755 not attempted (693 with no recipe); 307 of 307 recipe-backed rows carried forward | same atlas, `body.counts.by_subject`, `body.evidence_reuse`; `forensics/downstream/build-link-atlas.json` |
| **Library test suite** | **2,148 passing, 0 failing, 45 ignored** at `7bdc53d83` — a **floor**, not the current count: later commits add tests without a further full run | `atlas-refresh/test-baseline.json` (`full-library-run`) |
| **Memory safety: mechanisms** | **6 mechanisms discharged at mechanism scope** — RC-1 refcounting, OB-1 OwnedBuf release state, OB-2 OwnedStr string ownership, OB-3 OwnedCtx/RawCtx context ownership, ERR-1 ERR error-queue ownership and allocator file-coordinate seam, GEN-1 GENERAL_NAME selected-arm representation | `CAMPAIGN-STATUS.json` (`mechanism_discharges`) |
| **Memory safety: boundaries** | 5 scoped boundary discharges (B23, B25, B27, B28, B29); **B39–B40 independently checked**; B41–B43 batch-checked; B44 author-evidenced | `atlas-refresh/boundary-sweep-*.json` |
| **Memory safety: files converted / partial** | **877 files**: 92 `ZERO_UNSAFE`, 18 `BOUNDARY_COVERED`, 761 `PARTIAL` (audited 761/761), 6 `TEST_ONLY`, **0 unaccounted** | `atlas-refresh/unsafe-census.json`, `atlas-refresh/post-census-delta.json` |
| **`SAFE_COMPATIBLE` consumers** | **0 / 33** — no family has a proven dependency closure | `CAMPAIGN-STATUS.json` (`consumers`) |
| **BOUNDARY / SEAL gates** | **`NOT_RUN` / `NOT_RUN`** — no independent caller/dependency-closure audit, Miri/ASan/Loom/mutation control, authority differential, full forensic regeneration or held-out compatibility for the S16–S61 cluster | `CAMPAIGN-STATUS.json` (`gates.boundary_gate`, `gates.seal_gate`) |
| **Allocator / ABI invariants** | **preserved** — recorded invariant planes: `abi_courts`, `allocator_seam`, `exported_symbols`, `repr_c_layouts`, `unsafe_lints` | `CAMPAIGN-STATUS.json` (`structural_invariants`) |
| **Known gaps** | `S21-O1` CLOSED; `S22-RETAINED` RETAINED; `DOWNSTREAM-IMPLEMENTATION` 0 OPEN AT THE MEASURED IDENTITY; `DOWNSTREAM-h2o` CLOSED; `DOWNSTREAM-charybdis` CLOSED IN S61 (carried forward); `DOWNSTREAM-fastd` ENVIRONMENT; `DOWNSTREAM-HARNESS-FIXTURE` 76 CARRIED S59-S60 BLOCKERS + 25 NEW VENUE/BUILD BLOCKERS; `DOWNSTREAM-BELOW-L7` 101 FAMILIES; `DOWNSTREAM-S42-SYMMETRIC-LOSSES` CLOSED IN S44; `DOWNSTREAM-partclone` CLOSED; `DOWNSTREAM-perl-net-ssleay` CLOSED; `DOWNSTREAM-NO-RECIPE` 693 UNMEASURED; `DOWNSTREAM-MEDUSA` HARNESS; `DOWNSTREAM-S53-YIELD` 2 NEW L7 / 35 ADMITTED; `DOWNSTREAM-S60-YIELD` 7 NEW L7 / 30 ADMITTED; `S56-RESIDUALS` RETAINED; `S57-RACE` DATA-RACE FREEDOM NOT ESTABLISHED; `S58-SECURITY-CALLBACK` PERMISSIVE ARMS RETAINED; `S61-RESIDUALS` OTHER CALLBACK ARMS REMAIN PERMISSIVE | `CAMPAIGN-STATUS.json` (`known_gaps`) |
| **Release** | **Published: 0.0.41** on crates.io (2026-10-27), checksum `0d32b709…`, artefacts `libcrypto.so.3` `26ba36ff…` / `libssl.so.3` `1e7a9e8f…`. This evidence is bound to the 0.0.41 tree, which is the published 0.0.41 crate. 0.0.40 remains the previous release. | `atlas-refresh/publish-0.0.41.json`; `Cargo.toml` |

Downstream evidence reuse: **307 of 307 recipe-backed families carried forward** (`committed-rows-carried-forward`); `candidate_identity_match` = `false`. A carried-forward row is compatibility evidence from the build recorded on that row, not a fresh measurement at the identity above. The Safe-33 cohort has 33/33 of its families in that set.
<!-- END GENERATED: readme-achievements -->

### The families at `L7-functional`

<!-- BEGIN GENERATED: readme-l7-families -->
**209 of 1000 counted corpus families are `L7-functional`** — candidate 207 / authority 209 `L7-functional`; measured asymmetry: authority-only `ewftools`, `xilinx-bootgen`; 7 failed, 223 loaded, 307 recipes, 755 not attempted.

`afflib`†, `afftools`†, `aircrack-ng`†, `apache2-bin`†, `apache2-http2`†, `apache2-ssl`†, `apache2-utils`†, `appx-util`†, `apr-util`†, `arm-trusted-firmware-tools`†, `asterisk-srtp`†, `axel`†, `bannergrab`†, `bruteforce-salted-openssl`†, `carbon-c-relay`†, `casync`†, `charybdis`†, `cjose`†, `cowpatty`†, `curl`†, `curl-minimal`†, `cyrus-sasl`†, `cyrus-sasl-digestmd5`†, `cyrus-sasl-scram`†, `dcap-tunnel-ssl`†, `dcmtk`†, `dma`†, `dovecot`†, `duo_unix`†, `efitools`†, `eggdrop`†, `elinks`†, `epic5`†, `epic5-lite`†, `ewf-tools`†, `ewftools`†, `exim`†, `fetchmail`†, `fido2`†, `fossil`†, `fsverity-utils`†, `gensio`†, `getdns`†, `gftp-text`†, `git-crypt`†, `gmnisrv`†, `gostsum`†, `h2o`†, `h2o-evloop0.13`†, `haproxy`†, `hcxkeys`†, `hcxtools`†, `hiredis-ssl`†, `hitch`†, `httest`†, `httpd`†, `httperf`†, `httping`†, `httrack`†, `hydra`†, `icecast`†, `icecast2`†, `ima-evm-utils`†, `imapfilter`†, `iperf3`†, `ircd-hybrid`†, `ircii`†, `irssi`†, `isync`†, `jimtcl`†, `jwt`†, `kea`†, `keepalived`†, `kmod`†, `ldns`†, `ldnsutils`†, `lftp`†, `libafflib0v5`†, `libaprutil1`†, `libarchive`†, `libcjose0`†, `libcoap`†, `libcpp-httplib0.11`†, `libcrypt-openssl-bignum-perl`†, `libcrypt-openssl-dsa-perl`†, `libcrypt-openssl-ec-perl`†, `libcrypt-openssl-pkcs10-perl`†, `libcrypt-openssl-random-perl`†, `libcrypt-openssl-rsa-perl`†, `libcrypt-openssl-x509-perl`†, `libcrypt-smime-perl`†, `libdcmtk17`†, `libengine-gost-openssl`†, `libesmtp`†, `libevent`†, `libevent-openssl-2.1-7`†, `libevhtp`†, `libfsverity`†, `libgetdns10`†, `libjose`†, `libnetconf2`†, `liboauth2`†, `libpaho-mqtt`†, `librabbitmq`†, `librdkafka`†, `libre`†, `librelp`†, `libretls`†, `libssh`†, `libstrophe`†, `libtins`†, `libtpms`†, `libu2f-server`†, `libwebsockets`†, `libxmlsec1`†, `libzip`†, `lighttpd`†, `links`†, `lua-luaossl`†, `lua-sec`†, `lynx`†, `makepasswd`†, `memcached`†, `mini-httpd`†, `minizip-ng`†, `mktorrent`†, `monit`†, `monitoring-plugins`†, `mosquitto`†, `mumble-server`†, `mutt`†, `nagios-plugins-http`†, `nagios-plugins-ldap`†, `nagios-plugins-smtp`†, `nagios-plugins-tcp`†, `ncrack`†, `neon`†, `net-snmp`†, `nghttp2`†, `nginx`†, `njs`†, `nmap`†, `nmap-ncat`†, `nmh`†, `nrpe`†, `nsd`†, `opendkim`†, `openldap`†, `openssh`†, `openssh-client`†, `openssh-server`†, `openvpn`†, `osslsigncode`†, `partclone`†, `perl-crypt-openssl-aes`†, `perl-crypt-openssl-bignum`†, `perl-crypt-openssl-dsa`†, `perl-crypt-openssl-random`†, `perl-crypt-openssl-rsa`†, `perl-crypt-openssl-x509`†, `perl-crypt-smime`†, `perl-net-ssleay`†, `php`†, `poco`†, `postfix`†, `proftpd`†, `prosody`†, `proxytunnel`†, `pure-ftpd`†, `qpdf`†, `rabbitmq-c`†, `radsecproxy`†, `redis`†, `rhash`†, `rsync`†, `ruby`†, `s-nail`†, `s2n-tls`†, `shellinabox`†, `siege`†, `sipp`†, `sipsak`†, `slowhttptest`†, `slrn`†, `socat`†, `sofia-sip`†, `squid`†, `srt`†, `srtp`†, `sscg`†, `ssldump`†, `sslscan`†, `sslsplit`†, `ssmtp`†, `strongswan`†, `stunnel`†, `swtpm`†, `tcl-tls`†, `tcpdump`†, `tinc`†, `tnftp`†, `u-boot-tools`†, `unbound`†, `vsftpd`†, `w3m`†, `wrk`†, `xilinx-bootgen`†, `yara`†, `znc`†.

**† carried forward:** 209 of 209 listed rows are in `evidence_reuse.reused_families` (`committed-rows-carried-forward`, `candidate_identity_match=false`); they were not re-measured at the identity above. The Safe-33 cohort has 33/33 of its families in the same carried-forward set.
<!-- END GENERATED: readme-l7-families -->

Client, server, library, signing, interception, VPN, mail, DNS, IMAP, IRC,
XMPP, FTP, MQTT, Kafka, TPM, SNMP and digest/KDF faces are all represented. Each
row records a build against this crate's headers and libraries, linked with
`-Wl,--no-as-needed` so the subject libraries are provably loaded, and exercised
by a deterministic local workload with a negative control. The reconciled atlas
(`forensics/downstream/runtime-functional-atlas.json`, `body.counts.by_subject`
and `body.evidence_reuse`) records **candidate 207 / authority 209**
`L7-functional` out of **307 recipe-backed** families, with **223 candidate
loaded** (224 authority), **7 candidate failed** (5 authority), **755 not
attempted** and **693 with no recipe**. All 307 recipe-backed rows are
**carried forward** from the superseded identity
`dc17cfdd…`/`75cc3979…` (`evidence_reuse.mode =
"committed-rows-carried-forward"`, `families_reused = 307`,
`candidate_identity_match = false`); none is a fresh measurement at the identity
above, and every carried row names that superseded identity. The last full
no-reuse run (S52, 196 of 200 at `cd71d401`/`efd460de`) and the S59
re-measurement (198 of 216 at `c8a99c59`/`5992c29d`) remain history. The three
families lost in S42 (`dma`, `libssh`, `sslscan`) were recovered in S44, so the
Safe-33 cohort is 33/33. On the candidate side **100** of the 307 recipe-backed
families are below L7 (307 − 207), against **98** on the authority side; the
difference is the measured authority-only asymmetry `ewftools` and
`xilinx-bootgen`. `fdm` was repaired from ENVIRONMENT in S53, three fixtures
were lifted in S60, `charybdis` was repaired in S61, and **693** families have
no admitted recipe.

### Memory safety is partial — precisely what that means

This project does **not** claim to be memory-safe yet. The honest ledger is
derived from the receipts:

<!-- BEGIN GENERATED: readme-memory-safety -->
| Status | What it covers |
|---|---|
| **Discharged (mechanism scope)** | **6** — RC-1 shared reference counting; OB-1 OwnedBuf release state; OB-2 OwnedStr string ownership; OB-3 OwnedCtx/RawCtx context ownership; ERR-1 ERR error-queue ownership and allocator file-coordinate seam; GEN-1 GENERAL_NAME selected-arm representation. Mechanism scope only; not a file-level or consumer-level graduation. |
| **Discharged (scoped boundary)** | **5 receipts** — B23 (`B23-WPKT-1`, `B23-WPKT-2`), B25 (`B25-RL-4`, `B25-RL-5`), B27 (`B26-X1`), B28 (`B27-X2`), B29 (`B29-UI-1`, `B29-UI-2`, `B29-UI-3`). Retained boundaries stay `CONTRACTED`. |
| **Independently checked (not discharged)** | B39–B40 boundary-checked (memory-BIO constructor/destructor, connect-BIO descriptor); B41–B43 batch-checked; B44 **author-evidenced only**. |
| **Uninitialised-storage class** | **5 UNSOUND fixed** (4 owner-shaped + 1 frame-local), from 32 owner-shaped entries examined; 16 safe-by-construction and 12 misuse-resistant. CLOSED for the typed-accessor-over-uninitialised-storage class: both ml_dsa allocation surfaces and the scratch partition initialise before publication; the pkcs12 and bn owning-buffer accessors and the ssl t1_lib peer-sigalgs write no longer form a typed view over uninitialised storage. Retained: ml_dsa Vector::init / matrix_init remain safe constructors over caller raw pointers; they do not dereference, so no UB is reachable alone. Making them unsafe fn is the AGENTS.md section 1 end state, deferred because it touches about 20 call sites; x509::pcy_lib::tree_levels aliasing obligation (owner-derived borrow) remains retained; provider::cipher_gcm out-buffer slice formation was retained here in S22 and is now reconstructed: S40 eliminated getivgen's and gcm_tls_cipher's whole-extent typed slices over caller-writable output (OWNERSHIP_RECONSTRUCTED, not SAFETY_DISCHARGED) |
| **STOP-class defects** | **0 open** — `B27-X2` (`STOP-CLASS`, B27) **closed by B28**; `NEO-ERR-1` (`STOP_LEVEL`, B33) **fixed in B33**. |
| **Audited but not converted** | **761 `PARTIAL` files**; 761/761 audited, 0 remaining. Audit completion is not discharge. |
| **Not discharged** | Receipt-backed mechanisms still open: `BIO`, `RUNTIME_ALLOC_OWNERSHIP`; `SAFE_COMPATIBLE` remains 0/33. |
| **BOUNDARY / SEAL gates** | **`NOT_RUN` / `NOT_RUN`** — the S16–S61 cluster has no independent caller/dependency-closure audit, Miri/ASan/Loom/mutation control, authority differential, full forensic regeneration or held-out compatibility. |
| **Known gaps** | `S21-O1` CLOSED; `S22-RETAINED` RETAINED; `DOWNSTREAM-IMPLEMENTATION` 0 OPEN AT THE MEASURED IDENTITY; `DOWNSTREAM-h2o` CLOSED; `DOWNSTREAM-charybdis` CLOSED IN S61 (carried forward); `DOWNSTREAM-fastd` ENVIRONMENT; `DOWNSTREAM-HARNESS-FIXTURE` 76 CARRIED S59-S60 BLOCKERS + 25 NEW VENUE/BUILD BLOCKERS; `DOWNSTREAM-BELOW-L7` 101 FAMILIES; `DOWNSTREAM-S42-SYMMETRIC-LOSSES` CLOSED IN S44; `DOWNSTREAM-partclone` CLOSED; `DOWNSTREAM-perl-net-ssleay` CLOSED; `DOWNSTREAM-NO-RECIPE` 693 UNMEASURED; `DOWNSTREAM-MEDUSA` HARNESS; `DOWNSTREAM-S53-YIELD` 2 NEW L7 / 35 ADMITTED; `DOWNSTREAM-S60-YIELD` 7 NEW L7 / 30 ADMITTED; `S56-RESIDUALS` RETAINED; `S57-RACE` DATA-RACE FREEDOM NOT ESTABLISHED; `S58-SECURITY-CALLBACK` PERMISSIVE ARMS RETAINED; `S61-RESIDUALS` OTHER CALLBACK ARMS REMAIN PERMISSIVE |
| **`SAFE_COMPATIBLE` consumers** | **0 / 33** — no consumer family has a proven dependency closure. |
<!-- END GENERATED: readme-memory-safety -->

The planned conversion order is attacker exposure × eliminability: TLS state
machines and record processing first, then key schedule and targeted AEAD, then
the CMS mechanisms behind the unresolved CVE replays, then ASN.1/X.509 decode
and verification, then ML-DSA, then the remaining provider and algorithm cores.

**Current state:**
[`STATUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/forensics/STATUS.md) ·
[`SEAL-CENSUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/SEAL-CENSUS.md) ·
[`PARITY_MODEL.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/PARITY_MODEL.md)

## Where the memory-safety campaign actually stands (2026-10-27)

Receipts only. This is not a graduation and does not claim `SAFE_COMPATIBLE`,
constant-time behaviour, or that the BOUNDARY/SEAL gates passed.

- **V1 census** (`atlas-refresh/v1-candidate-freeze.json`): **381** uncontracted unsafe constructs in **152** files, **198** of them production.
- **V2 batch** (`atlas-refresh/v2-batch-floor.json`, `v2a-clippy-gate.json`): library suite **2151 passed / 0 failed / 45 ignored** in both serial and 4-thread modes; **42/42** adversarial probes at that time; **11/11** ABI courts; `cargo clippy --all-targets -- -D warnings` clean.
- **V3 instruments** (`atlas-refresh/v3-boundary-instruments.json`): Miri **9/9** under both Stacked and Tree Borrows, with **2** tests blocked by `pthread_once`; TSan **5/5**; Loom **4/4**; Kani **2** bounded invariants; MSan **2** focused paths, classed `RAN_BOUNDED_NOT_ADMISSIBLE` (uninstrumented libc) and not counted as a pass.
- **V3b real defect** (`atlas-refresh/v3b-error-leak.json`): ASan found an **84-byte** thread-exit `ERR_STATE` leak; the repair has a pre-fix negative control (destructor disabled fails and leaks; restored passes and is clean).
- **V4 closure** (`atlas-refresh/v4b-closure-precision.json`, `witness-rule.json`, `edge-targets.json`): the engine refuses `STALE_HASH`; the openssh closure reaches **2** production obligations, **both DISCHARGED**, and after the edge-target re-audit has **3** reachable unresolved sites — **2** contract-bounded and **1** target-bounded (`OSSL_PROVIDER_do_all`, application-supplied). The verdict is still `REFUSED` on `STALE_HASH`, not `ACCEPTED`.
- **Adjudications**: five consecutive openssh `SAFE_COMPATIBLE` adjudications were **REJECTED**, all on identity binding (`AGENTS.md` §22); the most recent is `atlas-refresh/graduation-openssh.json` (2026-10-27, `status: REJECTED`, superseding the 2026-10-26 rejection). `AGENTS.md` §22 now forbids that class of failure.

**Outstanding debts**

- `CAMPAIGN-STATUS.json` lag (partly fixed in this reconciliation).
- The court host checkout is bind-mounted read-write at `/work` (`AGENTS.md` §6).
- `docker/openssl-rs-court.sh` is committed mode `100644`, with no executable bit.
- S56/S57 races are not established; no faithful Loom model exists (`atlas-refresh/v3-boundary-instruments.json`, `s56_s57_loom`).
- Uncontracted production operations remain crate-wide: the V1 census records **198** (`v1-candidate-freeze.json`); the V1e rebind recomputes **67** (`v1e-candidate-freeze.json`), and no fresh full census has been regenerated.

## Where the conservation strata stand

The twenty-two strata and their subjects are in `docs/RELEASE_GATES.md` §1. Their
**derived state** is generated in
[`forensics/phase-state.md`](https://github.com/infinityabundance/openssl-rs/blob/main/forensics/phase-state.md)
by `forensics/tools/phase_state.py` and rendered into
[`STATUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/forensics/STATUS.md);
that generated file is authoritative over any prose, and this page does not restate
which strata are complete. For shape, the strata group as:

| strata | subject |
|---|---|
| 0–2 | the constitution, the archaeology, and the distribution shell — the `libcrypto.so.3` / `libssl.so.3` / `libcrypto.a` / `libssl.a` / `legacy.so` / `openssl` artefacts, headers, pkg-config and install tree, with the ABI courts that prove a binary built against the authority runs against the candidate unmodified |
| 3–17 | the substantive library strata: the runtime, BIO/CONF, `BN`/`ASN.1`/DER/PEM, the provider core, the EVP framework, the native primitives, RAND/DRBG, the key formats, X.509, the protocol families, legacy compatibility, TLS/DTLS, QUIC/ECH, the CLI/config contract, and the downstream replacement court |
| 18 | the hostile fuzz / security / side-channel hardening stratum |
| 19–21 | performance / CPU dispatch, the 3.6.4 custodian seal, and the maintenance-delta machinery |
| 22 | authority exhaustiveness and the whole-program compatibility atlas |

> **Safe-33 conversion status.** The generated blocker block below is frozen at
> the Phase-24 derivation and is superseded for current counts by the generated
> achievement block earlier in this page, which derives them from
> `forensics/downstream/runtime-functional-atlas.json`. For conversion,
> discharge, test-count and consumer claims read
> [`forensics/memory-safety/campaign/safe-c33/STATUS-2026-10-20.md`](forensics/memory-safety/campaign/safe-c33/STATUS-2026-10-20.md);
> `forensics/STATUS.md` is generated and requires regeneration by
> `forensics/tools/render_status.py` before its downstream figures can be
> quoted. No count is typed in this paragraph deliberately: typed counts go
> stale, which is exactly what the generated blocks exist to prevent.

<!-- BEGIN GENERATED: downstream-blockers -->

## Downstream-1000 biggest movers (generated)

Every one of the 1000 counted families, partitioned by its **deepest blocker** and the classes ranked by **mover potential**, with the feasible recipe queue, is in the
[generated report](https://github.com/infinityabundance/openssl-rs/blob/main/docs/PHASE-24-BIGGEST-MOVERS.md) (`docs/PHASE-24-BIGGEST-MOVERS.md`); the same table is cited by
`docs/SEAL-CENSUS.md`. This block is generated from
`forensics/downstream/shared-blockers.json` (the frozen Phase-24 derivation);
**do not edit it by hand.** Its figures describe that frozen plane; current
corpus counts come from `forensics/downstream/runtime-functional-atlas.json`.

| blocker class | families | mover potential | fixability | per-fix leverage |
|---|---|---|---|---|
| `no-admitted-recipe` | 965 | 965 | `recipe-admission` | 1.0 |
| `recipe-build-system-unsupported` | 2 | 2 | `recipe-build-system` | 2.0 |

**Frozen Phase-24 partition: 967 of the 1000 counted families are blocked; 33 are `DROP_IN_PASS`** (967 are `DROP_IN_NOT_APPLICABLE`, 33 measurable); of those 33, 25 were at L4-linked and 8 reached L5 or above in that plane. **Current atlas:** see the generated achievement block at the top of this page for the current candidate and authority `L7-functional` counts, the loaded and not-attempted split, and the cohort figure (`runtime-functional-atlas.json`, `body.counts.by_subject`; restated in `STATUS-2026-10-20.md`). The `drop-in-pass` figure is a baseline-normalized verdict count, not a rung.

* a selected population is not a random sample: the 1,000 counted families are selected from frozen ranking evidence, so their blocker shares do not generalise to all downstream software
* 1000/1000 is not a security proof: a full pass is not a guarantee that any consumer is safe, and the analysis makes no statement about an unmeasured consumer
* a build is not a functional proof: the configure/link/load rungs are not behaving, and only the functional levels are behavioural evidence
* direct and transitive consumers are different evidence: the two are never summed
* a heuristic ranking is not a measurement of buildability: the feasible recipe queue is ranked by frozen breadth signals, and no family in it has been built by this analysis

<!-- END GENERATED: downstream-blockers -->

## Compatibility target

The goal is substitution: an unmodified OpenSSL consumer should be able to
compile, link, load, execute, and observe the same externally visible behaviour
against the stated authority and build profile. The reconstructed distribution
artifacts are `libcrypto.so.3`, `libssl.so.3`, `libcrypto.a`, `libssl.a`,
`legacy.so`, provider modules, public headers, pkg-config metadata, and the
`openssl` executable, with their own symbol namespaces, SONAMEs and version
nodes. See
[`CUSTODIAN_CONTRACT.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/CUSTODIAN_CONTRACT.md).

Compatibility is evaluated independently across ABI, semantics, ownership,
error behaviour, state transitions, concurrency, correctness vectors, and
downstream behaviour. Passing evidence is scoped to the surface actually
exercised; unknown behaviour remains unknown.

## Verification

Compatibility is tested against the pinned OpenSSL build using **differential
courts**: one probe compiled against the authority and against the candidate,
whose transcripts are compared line by line. Construction correctness is a
separate plane of published test vectors, and ABI, symbol-ownership, prototype
and dispatch planes are checked independently. Results are retained as
machine-readable evidence and are not converted directly into compatibility
claims — promotion to `PARITY_VERIFIED` is per dimension, by court.

Which symbols are `SCAFFOLDED` and which are `IMPLEMENTED` — per library — is
generated in [`STATUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/forensics/STATUS.md)
under "Implementation state"; this page types none of those counts. No symbol is
`PARITY_VERIFIED`; that state is promoted only by a court, dimension by dimension
(`docs/PARITY_MODEL.md`).

> Generated evidence is authoritative over descriptive prose. Where a document
> and a generated artifact disagree, the artifact is right.

Evidence and method:
[`PARITY_MODEL.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/PARITY_MODEL.md) ·
[`REPRODUCIBILITY.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/REPRODUCIBILITY.md) ·
[`SEAL-CENSUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/SEAL-CENSUS.md) ·
[`DECISIONS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/DECISIONS.md)

## Build and test

Authority-bearing execution — differential courts, forensic probes, benchmarks
and authority builds — runs only in the isolated, resource-capped court
container, never on the host
([`CUSTODIAN_CONTRACT.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/CUSTODIAN_CONTRACT.md) §11).
Unit tests and static derivation may run outside it.

```bash
# build the pinned court image and start it with OOM protection
bash docker/openssl-rs-court.sh build
bash docker/openssl-rs-court.sh up
bash docker/openssl-rs-court.sh verify

# admit and build the pinned authorities, then generate the atlas
bash docker/openssl-rs-court.sh exec bash forensics/tools/build_atlas.sh

# build and test the implementation crate (fmt + clippy + tests)
bash docker/openssl-rs-court.sh exec sh -c 'cd /work && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test'

# long-lived evidence and sensitivity testing use a second, separately pinned
# tooling container (see docs/REPRODUCIBILITY.md §1.2 for why)
bash docker/openssl-rs-frf-court.sh up
bash docker/openssl-rs-frf-court.sh exec bash forensics/frf/run_courts.sh
```

The court applies hard resource caps (`--memory=8g --memory-swap=8g`,
`--pids-limit=2048`, `--cpus=8`, `--restart=no`) so a runaway court OOM-kills
inside the container rather than pressuring the host.

## Architecture

One Cargo package. One first-party implementation crate. No workspace, no
component crates, and no implementation dependencies: everything the product
does is implemented here. Internal modules may be arbitrarily numerous.

The single implementation still emits the multiple runtime artifacts the
distribution contract requires, with their own symbol namespaces, SONAMEs and
version nodes preserved. The crate's own type and the link machinery that
produces those artifacts are described in
[`Cargo.toml`](https://github.com/infinityabundance/openssl-rs/blob/main/Cargo.toml)
and [`ABI_POLICY.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/ABI_POLICY.md);
the directory layout of the evidence is documented in
[`REPRODUCIBILITY.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/REPRODUCIBILITY.md).

## Documentation

| document | governs |
|---|---|
| [`CUSTODIAN_CONTRACT.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/CUSTODIAN_CONTRACT.md) | mission, the single-crate rule, what "custodian compatible" means |
| [`PARITY_MODEL.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/PARITY_MODEL.md) | obligation states, evidence planes, promotion rules, residuals |
| [`RELEASE_GATES.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/RELEASE_GATES.md) | stratum order, maturity levels, court taxonomy |
| [`REPRODUCIBILITY.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/REPRODUCIBILITY.md) | receipts, determinism, court venue |
| [`SEAL-CENSUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/SEAL-CENSUS.md) | the generated obligations and courts census |
| [`DECISIONS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/DECISIONS.md) | the engineering decision record |

Additional policies — ABI, provider architecture, ownership and lifetimes,
concurrency, FIPS claims, `unsafe` Rust, security divergences, and non-claims —
are under [`docs/`](https://github.com/infinityabundance/openssl-rs/tree/main/docs).

## Limitations

- **Not FIPS validated.** Behavioural parity with the FIPS provider is not
  validation.
- **No cryptographic-security claim follows from OpenSSL parity.** Passing the
  OpenSSL oracle proves compatibility over the observed surface; it does not
  prove an implementation is cryptographically sound. Conversely, a perfect
  standards implementation can still be OpenSSL-incompatible.
- **Memory safety is measured, not established.** The memory-safety benefit of
  Rust is not asserted here: the crate still carries a large `unsafe` surface,
  measured per module by `forensics/tools/unsafe_footprint.py` and rendered in
  `forensics/STATUS.md` (58,767 unsafe sites and 10,860 `extern "C" fn` at the
  Phase 18 revision, 90.1% of them in the parser/algorithm modules rather than a
  boundary shim). `docs/UNSAFE.md` cites the generated table and the
  `UNSAFE-FOOTPRINT` growth ceiling; the count is a footprint, not a proof that
  the unsafe code is correct.
- **No universal claims from finite evidence.** Every claim names its authority,
  profile and platform.
- **Unknown is a research result.** `UNKNOWN` is reported, not traded for
  confidence.

See [`NON_CLAIMS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/NON_CLAIMS.md).

## Licence

Apache-2.0 OR MIT. Provenance for any OpenSSL interface material used for
archaeology is recorded in
[`NOTICE`](https://github.com/infinityabundance/openssl-rs/blob/main/NOTICE).
