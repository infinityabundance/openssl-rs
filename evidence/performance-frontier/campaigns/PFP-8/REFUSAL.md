# PFP-8 — validation-refusal tests

The optimisation was refused, so no validation or subgroup check was changed.
The tests below confirm the existing behaviour is identical to the authority at
the frozen digest, and record exactly which layer performs each check.

## `DH_compute_key` return codes

`differential.py` runs the exported `DH_compute_key` with the same 2048-bit
private exponent and seven peer values on each real group.

| peer value | meaning | candidate | authority |
|---|---|---|---|
| `0` | out of range / z = 0 | −1 | −1 |
| `1` | z = 1 | −1 | −1 |
| `p−2` | accepted exponentiation, valid range | value | value |
| `p−1` | z = p−1 | −1 | −1 |
| `p` | z = 0 (out of range) | −1 | −1 |
| `p+1` | z = 1 (out of range) | −1 | −1 |
| `2` | the group generator | value | value |

All 21 comparisons (7 values × 3 groups) agree. The `−1` arm is
`ossl_dh_compute_key`'s post-exponentiation `z <= 1 || z == p−1` refusal, which
raises `DH_R_BN_ERROR`-class reasons at the same sites; the public entry returns
the method's answer unchanged.

## Which layer validates what

* `ossl_dh_check_pub_key_partial` (range plus the `q` subgroup check where `q`
  is known) is called by the provider import and the ameth, not by
  `DH_compute_key`; it is untouched.
* `DH_generate_key`'s modulus and subgroup-size bounds and
  `ossl_ffc_params_simple_validate` are untouched.
* The `DH_compute_key` RFC 5246 unpadding loop is untouched.

## Repository gates

| gate | result |
|---|---|
| `cargo test --lib -- dh -- --test-threads=4` | **77 passed, 0 failed, 2 ignored** |
| `cargo test --lib -- --test-threads=4` | **2,493 passed, 0 failed, 54 ignored** |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |

The `dh` filter includes the TLS 1.2 DHE negative controls
(`tls12_dhe_not_prime_is_rejected`, `tls12_dhe_oversized_prime_is_rejected`,
`tls12_dhe_short_prime_is_rejected`, `tls12_dhe_zero_public_value_is_rejected`),
the generated-group agreement test, and `ossl_dh_buf2key` range refusals.
