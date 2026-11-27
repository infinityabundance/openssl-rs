# PFP-4 — the design that was not built, and why

This file records the conversion PFP-4 describes so a future session does not
have to reconstruct it. **None of it is implemented**: the W3 bound
([`BOUND.md`](BOUND.md)) shows the arithmetic it would rewrite is 0.45 % of
signing wall time, so building it cannot move `ecdsa256`. It is written down as
design evidence, not as a claim.

## 1. The types already exist

PFP-2 landed `P256Scalar` (`src/ec/p256.rs`), a fixed-width 4-limb residue
modulo the group order in Montgomery form (`Mont<OrderDomain>`), with
`from_canonical_reduced`, `to_canonical`/`to_be_bytes`, `mul`, `add`, `sub`,
`select`, `cswap`, `reduce_wide`, `is_zero_mask` and `admit_be_bytes`. PFP-4
would consume this type rather than introduce one.

The admission precondition would be exactly PFP-3's
(`fixed_base::admits`, `src/ec/p256/fixed_base.rs`): the group's prime, `a = p−3`,
`b`, order, cofactor, generator and the plain-ladder method must all match the
tracked P-256 parameters. Any other group, generator, curve or method keeps its
current generic path unchanged. This is the same predicate PFP-3 already uses
for the `k·G` arm, so the specialised signing pipeline would be reachable only
where the fixed-base comb is reachable.

## 2. Scalar arithmetic mod q

`mul`, `add` and `sub` are the kernel's existing `Mont<OrderDomain>` operations.
`add`/`sub` route through `add_canonical`/`sub_canonical`, which perform the
final conditional subtraction with a full-width mask and no branch on the value;
`mul` uses `mont_reduce_into`, whose release-profile branch removal is PFP-2's
recorded `790685a0aa` fix. A new path would not add a value-dependent branch.

## 3. `k⁻¹ mod q` — choice and fixed iteration count

Two candidates were analysed, as the item requires:

| option | fixed iteration count | dependency | reasoning |
|---|---|---|---|
| **Fermat, `k^(q−2) mod q`** | **256 squarings** + a multiplication on each set bit of the *public* constant `q−2` | reuses `P256Scalar::sqr`/`mul` | the exponent is a public compile-time constant, so branching on its bits is public-bound (the same discipline as `fixed_base::invert` for `p−2`); the base is secret and only ever feeds constant-time field multiplications |
| Bernstein–Yang divstep | ≈590 fixed iterations for a 256-bit modulus | new 2-adic/divstep kernel | shorter dependency chain per iteration but a new arithmetic core to design, test and audit |

**Choice: Fermat**, because the exponent is public (no secret-dependent control
flow), it reuses the already-audited `P256Scalar` Montgomery kernel, and its
iteration count is a fixed 256 independent of the secret. The measured cost
basis: the *field* Fermat inverse (`p−2`) is 7.34 % of signing `Ir` with the
specialised kernel, while the *order* inverse is 15.91 % because it runs on the
generic `bn::arith::mont_mul_sos_into`. A `P256Scalar` Fermat inverse should
therefore land near 7–8 %, i.e. roughly halve the 12.7 % wall share of the
inversion. This is why the inversion is the only PFP-4 component with headroom,
and why it is recommended as a separate task rather than bundled here.

The differential obligation (a wrong inverse is a catastrophic silent failure)
would be: every admitted input plus the edges `0`, `1`, `2`, `q−2`, `q−1`,
2^k boundaries, top-limb-clear values and a large pseudorandom population,
compared limb-for-limb with the existing `ec_field_inverse_mod_ord` oracle; a
single mismatch is a STOP. That obligation was **not run**, because no inverse
was written.

## 4. The signing expression and export

`s = k⁻¹·(m + r·d) mod q`, all in `P256Scalar`:

* `r` is already reduced from the field to the order in `ecdsa_sign_setup`
  (`BN_nnmod(r, x, order)`), and `m` is reduced once from the digest
  (`BN_nnmod(m, m, order)`), both on public control flow (the digest is
  `PUBLIC_DATA`); these steps would keep their current reductions.
* the sum `r·d + m` uses the kernel's mask-reduced `mul`/`add`;
* the product by `k⁻¹` uses the kernel `mul`.
* **Export** converts `r` and `s` through `P256Scalar::to_be_bytes` into the same
  big-endian `BIGNUM` values `i2d_ECDSA_SIG`/`ECDSA_sign_ex` emit today; the DER
  encoding, `ECDSA_sign_ex`, supplied nonces, custom methods, retries and error
  behaviour would be preserved byte for byte, and a supplied nonce would still
  be used exactly as given.

## 5. T27 (constant-pattern addition) is not bypassed

The constant-pattern addition required by the row is
`bn::arith::mod_add_reduced_ct` (`src/bn/arith.rs`), called at the `s = s + m`
site in `ossl_ecdsa_simple_sign_sig` (`src/ec/ecdsa_ossl.rs:762`). It is
unchanged: no source file was modified by this batch. A future specialised
expression would have to either keep that call or use a kernel add with the same
fixed-pattern property; it could not replace it with a value-branching add.

## 6. Blinding

No new path was added, so blinding semantics are unchanged. The only specialised
base of the pipeline is PFP-3's fixed-base comb, which multiplies the public
generator `G`, not a secret point; coordinate blinding on `G` protects nothing.
Nothing in the PFP-4 design would have changed that.
