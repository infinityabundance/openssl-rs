# PFP-5 — taint and binary branch audit

## 1. ctgrind (valgrind memcheck, `VALGRIND_MAKE_MEM_UNDEFINED`)

The cases are in the **debug test binary** built from the same source tree
(`sha256 4d998db64ed7d49b943e01f44f2b2991b637e262606bac59e1553a9dd339aa9e`).
This is the repository's recorded convention for the BN/RSA cases; it is
**source-bound, not DSO-bound**. DSO-level ctgrind is PFP-21's concern and is not
claimed here.

| case | tainted | gate | errors | contexts | window contexts |
|---|---|---|---:|---:|---:|
| `bn::arith::tests::ctgrind_secret_exponent_window` | exponent limb bytes only (length defined) | `--exact … --test-threads=1` | **0** | **0** | 0 |
| `rsa::ossl::tests::ctgrind_rsa_crt_secret_exponents` | `d`, `dmp1`, `dmq1`, `p`, `q` | as above | 96,821 | 112 | **0** |
| `rsa::ossl::tests::ctgrind_rsa_crt_secret_moduli` (baseline) | `p`, `q` only | as above | 96,659 | 112 | **0** |

* The **modexp** case taints the secret exponent and runs the window path end to
  end: **0 errors from 0 contexts**. No conditional jump and no memory address
  depends on the exponent, the window digit, the scanned table row or the
  accumulator. The scan introduces no secret-dependent transfer.
* The RSA exponent-and-key case is **within the recorded band** (PFP-1 recorded
  96,541/106, 96,836/112, 97,626/111, 96,155/105) and has the **same 112
  contexts** as the moduli-only baseline at this digest. The additional
  exponents change neither the context count nor the origin sites: the residue
  is the pre-existing variable-time `mod_exp_core` used by the RSA public-exponent
  verify step, and the `BN_sub`/`BN_add`/`BN_mul`/`BN_nnmod` and `ladder_geometry`
  (modulus evenness) sites — all present before PFP-5.
* `grep run_mont_ladder_window|select_window_digit` matches **0** lines in both
  RSA logs and in the modexp log.

**A secret-derived transfer would have been a STOP. There was none.**

## 2. Binary branch audit at the candidate digest

`courts/phase18/timing/binary_branch_audit.py` with an explicit targets file,
`--expect-sha256 842efa27…`, exited 0: both targets resolved uniquely with
complete, contiguous disassembly.

`run_mont_ladder_window` and `select_window_digit` are inlined into
`run_mont_ladder`; `redc_into` is inlined into `mont_mul_sos_into`.

| carrier | bytes | insns | jcc | div/idiv | cmov | setcc | jo/jno | loop | calls | cpuid |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `run_mont_ladder` (window + scan) | 5821 | 1255 | 100 | **0** | 2 | 18 | 2 | 0 | 70 | **0** |
| `mont_mul_sos_into` (REDC) | 1013 | 249 | 19 | **0** | 0 | 10 | 0 | 0 | 5 | **0** |

### Classification

| family | count | operands | class |
|---|---:|---|---|
| `run_mont_ladder` jcc | 100 | loop back-edges over public counters (`hi`, `k`, `j`, entry index, window start); allocation/`Option`/`checked_*` failure checks; slice bounds on public indices; the kernel's `bool` geometry result | **public-bound** |
| `run_mont_ladder` setcc | 18 | capacity overflow (`seta`/`sete` pairs in `try_zeroed`) and slice-bounds comparisons (`setb`) on public pointers/indices | **public-bound** |
| `run_mont_ladder` cmov | 2 | slice pointer selection under public bounds | **public-bound** |
| `run_mont_ladder` jo/jno | 2 | checked-arithmetic overflow on public lengths | **public-bound** |
| `run_mont_ladder` calls | 70 | `mont_mul_ladder_into`, `constant_time_eq_s`, allocator/cleanse helpers | public dispatch; no CPU-feature dispatch (`cpuid` = 0) |
| `mont_mul_sos_into` jcc/setcc | 19 / 10 | the pre-existing REDC mask-select and carry logic; unchanged by PFP-5 | public-bound (PFP-6 record) |

**Secret-derived entries: none.** The digit, the table contents and the
accumulator are consumed only by shifts, `constant_time_eq_s` masks and
bitwise AND/OR; the taint run above confirms the compiler emitted no control
transfer or address on them.

**Limits.** The audit says what instructions were emitted; it does not prove
secret-independence by itself. The taint run is the independence evidence and it
is source-bound (test binary). ctgrind reports control flow and addresses, not
variable-latency instructions; this is not a constant-time proof.
