# Gemel trajectory (generated projection)

Generated from the local `.gemel` store by
`forensics/tools/render_gemel_trajectory.sh` inside the FRF tooling
container. Gemel's store is **not** Git-tracked (Gemel ships a
`.gemel/.gitignore` containing `*`), so this projection, Gemel's own
`exchange/` namespace, and the identities quoted below are what travel
in Git. See `docs/DECISIONS.md` D17.

## `gemel log`

```
C21  The BN surface is closed: every one of the 201 exports bn.h declares is implemented or handed to a named later stratum, and the stratum court now covers the whole of it. Six new modules: mont (BN_MONT_CTX and the Montgomery arithmetic over it, with R = 2^ceil(bits/64)*64 as the authority picks it), recp (BN_RECP_CTX and reciprocal division, whose quotient and remainder the probe checks against BN_div directly because the reciprocal is a speed device and not a different division), primes (the thirteen named primes, whose values are generated from the authority by forensics/tools/gen_bn_primes.py rather than transcribed, and whose five static NIST objects are cached so two calls answer the same pointer the authority returns), nist (the five reducers and the value-based selector), kron (BN_kronecker, Cohen 1.4.10 including the reciprocity sign written the way the authority writes it), and blinding (BN_BLINDING: new/free, the flag and thread surface, the lock, and invert/invert_ex). The court went from 475 to 577 observations over 0 residuals, and extending it found one defect which was again the probe: the first version handed BN_mod_exp_mont a BN_MONT_CTX re-set to a different modulus, and the authority answered 0 for it because a context is bound to one modulus. With a matching context everything agreed on the first run, and two claims the source only suggested are now measured: that BN_nist_mod_* is BN_nnmod against a fixed prime and ignores the field argument it is handed, and that BN_nist_mod_func selects by value rather than by identity. Thirty-one BN exports are handed to Phase 9 with the dependency as the reason: the RAND families, the prime generators, the five Miller-Rabin primality tests, the X931 generators, BN_generate_dsa_nonce, the GF2m square-root and quadratic-solver pair, and the four blinding entry points that re-create the blinding factor through BN_BLINDING_create_param. Fifteen remain open and all of them are GF(2^m): add, arr2poly, poly2arr, mod, mod_arr, mod_mul, mod_mul_arr, mod_sqr, mod_sqr_arr, mod_exp, mod_exp_arr, mod_inv, mod_inv_arr, mod_div, mod_div_arr. Phase 5 is in-progress and derived: 333 open of 1099 covered, 280 ASN.1, 15 BN, 38 PEM. FRF: run 92c14e395079b876c00b21062faaff4d887ddb913419eb73ea6c1efd9e2e17c4, receipt bfc1b9169a88d2e60a682a69612465eb6b520e653097ba3f75719d6f07b8df82, challenge 551ff830a4b500afa06a1c117f842434634e470122b35e0f5cb0c97cafc70301, claim 62ccbb07477191b275df2601447473095452b7b409c94b0d56b8059bab507b43. The prototype court added in the previous change is now a CI gate and reproduces in evidence_determinism: 550 of 610 implemented exports checked, 0 mismatches.
    state state.ebcc96f517c951fc5431bb54f9e43b20a390d8f6c6d8645b10598f83edcf4c1e -> state.a5011f9ae7e414dd7ad7814c7bf30290fb1bc84ae250838d4d8683ad552b4db6
C20  Phase 5 BN arithmetic closed, and the court that closed it found nine behaviours first. RT-BN compiles one C probe against the admitted authority and against the candidate and diffs the transcripts: 45 residuals on its first real run, 0 at closure, over 475 observations. The first run was a probe bug (a freed BIGNUM slot reused through BN_asc2bn, because BN_free does not clear the caller pointer) and that is the tenth time in this project that the probe was the suspect. The 45 were real: BN_bn2hex is byte-oriented and not nibble-oriented (32 of them were one nibble wide), BN_cmp orders by sign before magnitude and negating the magnitude answer inverts exactly the mixed-sign case, BN_asc2bn answers 1 or 0 and not a digit count, BN_usub reports only a limb-count shortfall and otherwise lets the final borrow escape, BN_mask_bits reports a width past the value top limb, the mod family reduces last rather than first so a negative operand contributes its sign, the _quick variants are their own algorithms, a negative exponent is not rejected because the ladder reads the magnitude, and the error queue is part of the answer at the authority own coordinates (all nineteen raising crypto/bn translation units now covered by gen_err_raise_sites.py). One residual was a panic rather than a wrong value: BN_mod_inverse(a,0) reached limbs::rem division-by-zero assertion, which guard_ffi caught into a null return with no error raised because the raise happens after the arithmetic; limbs::mod_inverse now answers None for a zero modulus, which is also the mathematically right answer. The most important finding was a call convention: BN_signed_lebin2bn and its relatives were declared -> c_int while the authority declares BIGNUM *, and they required a non-null ret, so the documented NULL-means-allocate form failed. The atlas recorded the prototype and nothing compared it, so forensics/tools/prototype_court.py now compares return class and arity for every implemented export (resolving both sides through their typedef chains so spelling never reads as shape), with symbols it cannot check named by class and never counted as passes. Its first real run found two more, in this stratum own new code: BN_CTX_new_ex and BN_CTX_secure_new_ex carried a const char *propq that belongs to the EVP constructors and not to these, harmless at every call site on this ABI which is exactly why only a prototype comparison finds it. Recorded: the RAND-dependent exports of this stratum (BN_rand family, BN_generate_prime family, BN_generate_dsa_nonce, BN_BLINDING_create_param, the X931 generators and the GF2m sqrt/solve_quad pair) are handed to Phase 9 with the dependency as the reason; the two ABI_ONLY_EXPORTED symbols the atlas has no prototype for (OPENSSL_DIR_read, OPENSSL_DIR_end) are reported rather than skipped. Phase 5 is in-progress and derived: 391 open of 1099 covered, 280 ASN.1, 73 BN, 38 PEM. FRF: run-openssl-rs-rt-bn-5580515d5fb3a457d26b65acfbb5b448e525df3a596f248f74418b3f55d3fdef, receipt f58c3b404fe7832043ddeca4fa58ad8dbec69b3beed1071a5502e4be7e9350bf, challenge 37815ebd91f5a0fc28e7417539a4706bb0fef1e577fa256c495dfcd5d4d112e9, claim 7648b6178e10d5b50f9dae13fcc0335283737f5abe7ec259d5ea18973c17f69c.
    state state.3b639aa874b366dd8e46bfd6d8f395c89cfa35c9b813f0f5c3ac260c43531c51 -> state.ebcc96f517c951fc5431bb54f9e43b20a390d8f6c6d8645b10598f83edcf4c1e
C19  Phase 5 archaeology and the BN substrate. The stratum owns 513 of the authority exports, measured rather than typed: 201 in bn.h, 274 in asn1.h/asn1t.h and 38 generic PEM entry points, with 580 handed to later strata by declaring header (23 to phase 7, 58 to 8, 12 to 10, 346 to 11, 141 to 12). The families had to be derived because the candidate surface spans 270 distinct ASN.1 type names and prefix lists cannot separate d2i_X509 from d2i_ASN1_INTEGER; typed families are also how the D49/D51 defect class arose twice. The ledger fails closed on an unknown header. The BN substrate is written but not committed and not wired in: making the entry points unsafe extern C cascades into about sixty internal SAFETY comments, and there is no differential court yet, so committing would put symbols in the ABI shell as implemented on unit-test evidence alone. Twelve limb unit tests pass, and three of their expectations were wrong while the implementation was right.
    state state.e0c7044436a5db04f8a67931be2e8532bae6af04741d0789a736157bd367f2ab -> state.3b639aa874b366dd8e46bfd6d8f395c89cfa35c9b813f0f5c3ac260c43531c51
C18  Phase 4 evidence reproducibility: the RT-BIO-DEBUG probe leaked an ASLR-dependent subject address to stderr through the NULL-destination fallback of BIO_debug_callback_ex. The court declares stdout and exit as its axes, and its stdout was already stable and scrubbed, so the claim was never affected; but the capture includes stderr, so every run produced a different evidence identity, and that one court was enough to make the aggregate runtime claim identity unstable. Measured: three re-runs of the court in one store produced three different run ids. setarch -R is refused in both court containers, so ASLR cannot be disabled. The probe now redirects descriptor 2 to a temporary file for that one call, restores it, and reports the scrubbed text as two further observations. Three re-runs now return the identical run id and FRF refuses to re-capture, which is the falsifiable test that it is fixed.
    state state.6362a83c6c38c4083b7e282c2c06129d5e2c180c6f75f473b2f79f8cba98f7a5 -> state.e0c7044436a5db04f8a67931be2e8532bae6af04741d0789a736157bd367f2ab
C17  Record correction: the Phase 4 ledger hands thirty-one exports to later strata, in five groups, each with a named owning phase and a stated reason. Six to Phase 5 (the ASN.1 prefix and suffix hooks plus BIO_f_asn1 and BIO_new_NDEF), seventeen to Phase 6 (BIO_s_core, BIO_new_from_core_bio and the fifteen CONF module-registry entry points), five to Phase 7 (the digest, cipher, reliable and base64 filters and BIO_set_cipher), one to Phase 9 (BIO_f_nbio_test, whose read and write call RAND_priv_bytes), and two to Phase 12 (BIO_new_CMS and BIO_new_PKCS7). The eleven symbols Phase 3 handed to Phase 4 are recorded on the Phase 3 side as discharged, not as Phase 4 deferrals. No file content changed.
    state state.6362a83c6c38c4083b7e282c2c06129d5e2c180c6f75f473b2f79f8cba98f7a5 -> state.6362a83c6c38c4083b7e282c2c06129d5e2c180c6f75f473b2f79f8cba98f7a5
C16  Record correction: the Phase 4 closure change C15 says the ledger hands twenty-two symbols to later strata. The ledger hands thirty-one, and two of the thirty-one are the ASN.1 prefix hooks and CMS/PKCS#7 BIO bindings; the eleven discharged Phase 3 hand-offs are counted on the Phase 3 side, not as Phase 4 deferrals. No file content changed with this correction; the Git commit remains the authoritative record of the diff.
    state state.6362a83c6c38c4083b7e282c2c06129d5e2c180c6f75f473b2f79f8cba98f7a5 -> state.6362a83c6c38c4083b7e282c2c06129d5e2c180c6f75f473b2f79f8cba98f7a5
C15  Phase 4 complete: sixteen differential BIO, BIO-adjacent, OBJ and CONF courts with no residual over 3215 observations; the whole CONF reader including both character-class tables; the lhash insertion-order defect the dump text exposed; the ERR data formatting the authority does through BIO_vsnprintf; and a ledger that hands twenty-two symbols to named later strata. The FRF runtime claim is now sensitivity-backed over twenty-three courts.
    state state.6fe2d6a4caa8fde4a5aed8933bcac4e4a7e403eb92165dfc85b56f54dfce9c5a -> state.6362a83c6c38c4083b7e282c2c06129d5e2c180c6f75f473b2f79f8cba98f7a5
C13  Record correction: Gemel names changes by derived order, so the name C9 that Phase 3 closure (change.0321160b...) quotes in its summary is not stable. The placeholder change it means is change.e58167ada98b43af520cd6b8c39c103a30560c406cfd91e6004019fd0b75f326, currently named C11, and it is the change that carries the Phase 3 working-tree operations because it was created first. No content changed; this change exists so the durable identity is recorded in the store rather than only in prose.
    state state.fad064947e65109210abd9e4d2e1a79a9945c6dc6604c8d6c74501c1d5f1045c -> state.6fe2d6a4caa8fde4a5aed8933bcac4e4a7e403eb92165dfc85b56f54dfce9c5a
C10  Phase 3 complete: seven differential runtime courts with no residual, generated ERR reason tables and raise-site coordinates, load-gated string visibility, fail-closed obligation ledger. Supersedes C9, which was created accidentally by a command-line probe of the claim-kind enum and carries only a placeholder claim.
    state state.fad064947e65109210abd9e4d2e1a79a9945c6dc6604c8d6c74501c1d5f1045c -> state.fad064947e65109210abd9e4d2e1a79a9945c6dc6604c8d6c74501c1d5f1045c
C11  p
    state state.46cf9bcff7dad1b49b613c87d2458196666c4d2e787c76ea29702255e3913716 -> state.fad064947e65109210abd9e4d2e1a79a9945c6dc6604c8d6c74501c1d5f1045c
C6  Phase 2.1 structural closure: dynamic contract, exact symbol comparison, evidence-derived phase state
    state state.ba6b30cf8a7741640b349cf65bff4a30247994151265f119bd5f2d6a4073a42b -> state.46cf9bcff7dad1b49b613c87d2458196666c4d2e787c76ea29702255e3913716
C5  Phase 2 complete: distribution shell, ABI matrix, substitution, constants, FRF ABI court
    state state.c86c4178c1597a82a06176665f752d3aa9107c30b5be2178f67ba5d5f4526621 -> state.ba6b30cf8a7741640b349cf65bff4a30247994151265f119bd5f2d6a4073a42b
C2  Phase 1 foundation closure: differential atlas, completeness, FRF sensitivity-backed claim, FFI boundary
    state state.85d1e8ede88fb9f355d3d7e01f71483f9b28f0a857898a706a5fe5a3099a44f2 -> state.c86c4178c1597a82a06176665f752d3aa9107c30b5be2178f67ba5d5f4526621
C1  Phase 0 constitution and Phase 1 archaeology atlas, evidence-bound
    state (initial) -> state.85d1e8ede88fb9f355d3d7e01f71483f9b28f0a857898a706a5fe5a3099a44f2
```

## Checkpoints

* `K1` — `checkpoint.2a1ca2279b999e7740976a4958d6d6bb66e5312203ed9d15816d340a38073328`
* `K10` — `checkpoint.51ac8d8e9e91d360fe1bb94630661f0fd4071dd844baa1cd42c82b4e1504ba08`
* `K11` — `checkpoint.843b3f72da905eec1a0fc67a16ee8f1dc4811f86f51dfa75ae68a4d0c88ac4c6`
* `K2` — `checkpoint.67a75f9a16d008e6e5aec0984c93dfc7549bd7a33708b909fbf6424b04fcb4a6`
* `K3` — `checkpoint.b1516eb6364ad075785911cb204a75a6e1b83b08c1a7ca39a2de6e3983dc9aed`
* `K4` — `checkpoint.1bde75b37e1ca3972037c29cbd3ba5291079544436db9176a82f097a6bf832fe`
* `K5` — `checkpoint.6b0d12f1ecf380c0808bc95675222fbed7256f99bc8e9f475a0ec2693f804a0a`
* `K6` — `checkpoint.8958092650197b473c5b00d9c0de22e075c4765efc2e8a4ab9d452ffae97cf61`
* `K7` — `checkpoint.0c5d62d5f78d2c4ebdc7174affd4464f04d1315708e5a87962cded63439818d3`
* `K8` — `checkpoint.7eb3dba97cbf20f2b34d14cce7e93bc2171ebd0d7ee66d1f7508cc6e199567de`
* `K9` — `checkpoint.60105b4c8189d2668c48e173fe2c92c0ddf76160caae24efecc707bd576f506f`

current: `checkpoint.843b3f72da905eec1a0fc67a16ee8f1dc4811f86f51dfa75ae68a4d0c88ac4c6`

## Note: derived names are not identities

Gemel names changes by derived order, so a name quoted inside one change's
summary can be renumbered later. The Phase 3 closure change
(`change.0321160b791013c5904bb61fe65b4932da674bdbc7f1043b50e2e4369544c227`)
says it supersedes `C9`; that name no longer exists in the store. The change it
means is
`change.e58167ada98b43af520cd6b8c39c103a30560c406cfd91e6004019fd0b75f326`,
currently named `C11`: a placeholder created by a command-line probe of Gemel's
claim-kind enum, which — because it was created first — is also the change that
carries the Phase 3 working-tree operations. The correction
(`change.8423b2c8fe75201fb070e0b21df03d122c8675cde393c9b2d88d9ea1800ee5de`)
records that mapping in the store rather than only in prose. No file content
changed with it; the Git commit is the authoritative record of the diff.

## Open residuals at this boundary

```
open [low] BN_rand, BN_generate_prime and the other RNG consumers in bn.h are owned by phase 5 but cannot be built before the RAND stratum exists; deferring them to phase 9 on the precedent of BIO_f_nbio_test is the decision still to take
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [medium] the BN entry points need an unsafe extern C conversion plus about sixty SAFETY comments before the crate lint gate passes
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [high] the BN substrate is written but unwired and uncourted, so no BN symbol is implemented in the ABI shell and the ledger reports 513 open
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the RT-BIO-DEBUG transcript gains two observations, so its receipt identity differs from the one recorded before this fix
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] thirty-one Phase 4 family exports are handed to a named later stratum and remain SCAFFOLDED until it lands
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] the ABI-SYMBOL court compares name, version, ELF type, binding and visibility but never C prototypes; a declaration/definition arity mismatch is invisible to it
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] CONF_get1_default_config_file answers the empty string rather than the forensic build OPENSSLDIR; OBL-CONF-DEFAULT-CONFIG-FILE is owned by Phase 16
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] the FRF runtime claim covers the first stdout line, which is a digest of the whole transcript, plus exit class; stderr is not claimed because both sides write none
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the CONF court cannot compare parselist.nocb or the recursive-directory include, because the authority faults on both
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] Gemel C9 was created accidentally while probing the claim-kind enum, and Gemel is append-only so it carries a placeholder claim; C10 is the substantive record
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] the FRF runtime claim covers the first stdout line, which is a digest of the whole transcript, plus exit class; stderr is not claimed because both sides write none
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] two authority ERR raise arms (stack.c:212 and stack.c:275) need on the order of a billion elements to reach; their conditions are reproduced but no court exercises them
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the ABI-SYMBOL court compares name, version, ELF type, binding and visibility but never C prototypes; a declaration/definition arity mismatch is invisible to it, and one was found this phase by the RT-ERR probe instead
    class: verification_gap
    persistence: 0 descendant change(s)
superseded [low] FRF sensitivity coverage missing for the two non-fixture-driven courts, harness disposition, blocks a sensitivity-backed claim for them
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] candidate DSOs carry toolchain runtime dependencies the C authority does not; recorded by ABI-DYNAMIC, not removable from a Rust-linked artifact
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] Every shell symbol is SCAFFOLDED and aborts when called; Phase 2 proves structure, never semantics
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] Two macros added in 3.6.4, one of which (X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH) is security-fix related
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] OpenSSL 3.6.3 to 3.6.4 version banner divergence, disposed as an oracle-version trajectory
    class: expected_mismatch
    persistence: 0 descendant change(s)
```
