# PFP-22 — differential domain completion at candidate `553e1b8c`

- **Item:** PFP-22 (differential domain completion).
- **Candidate:** `553e1b8ce1eb7e03a0d92a5614b566b88e49e55d2c2a3f7ba28fc6d78eecc4e4`
  (`court/tmp/pfp21/a/distribution/libcrypto.so.3`, the PFP-20/PFP-23 artefact).
- **Authority:** `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2`
  (OpenSSL 3.6.4 production authority).
- **Venue:** court container `openssl-rs-court-tools:1`, 8 GiB cap, kernel 7.3.5-2-cachyos,
  x86_64, `cc` 12.2.0.
- **Result:** **PASS** — every class ran on both subjects and agreed, including the
  rejection of an off-curve point. No mismatch anywhere.

## Instrument and identity

The measurement instrument is the PFP-2 DSO-bound court (`pfp2_dso_differential.c`,
source `fd67b943…`): one process `dlopen`s exactly one `libcrypto.so.3` with
`RTLD_NOW|RTLD_LOCAL`, prints `LIB` from `dladdr(BN_new)` and
`LOADED realpath/dev/ino/size` plus `MAPS entries`, and the runner compares those with
`stat(2)` on the expected on-disk DSO. Every case is serialised with
`EC_POINT_point2oct(POINT_CONVERSION_UNCOMPRESSED)` and compared byte-for-byte
between candidate and authority. Nothing is rebuilt; the candidate is the frozen
distribution DSO.

The only extension is the population generator. Its source is
`pfp22_domain_differential.c` (sha256 `0aa2695e…`, binary `06a75088…`). The loader,
identity proof and comparison are carried over unchanged; the original `mul-g` /
`mul-p` modes call the original `bytes_for`/`scalar_for` and emit the original line
format, and their `.points` digests reproduce the historical ones exactly (see
*Comparability*). For the population classes the actual SEC1 octet length is
recorded, so the point at infinity (one `0x00` byte) is compared rather than being a
fatal error.

Identity proof: **18/18 rows `ok`** (9 classes × 2 subjects), each mapped file equal to
its `stat(2)` `realpath`, device, inode and size, with ≥ 1 `/proc/self/maps` entry:

| subject | dev | ino | size | maps entries |
|---|---|---|---|---|
| candidate | 57 | 1985086 | 17032672 | 5 |
| authority | 57 | 325854 | 7295816 | 5 |

Raw rows: `raw/identity-check.tsv`. The candidate and authority digests are checked
before and after execution (`raw/run-meta.env`).

## Population (each class has its own seed and case count)

`seed` words are mixed by the original `splitmix64` construction. `upper-*` uses
rejection sampling: set the top bit (so the value is ≥ 2^255), and redraw if the
value is ≥ q (acceptance probability `1 − 2^-32`), giving a uniform draw from
`[2^255, q−1]`. The authority and candidate do not derive anything themselves; the
harness supplies identical bytes to both.

| class | mode | seed | cases | derivation |
|---|---|---|---:|---|
| base-mul-g | mul-g | `0x5046503250485032` | 4096 | original `scalar_for` generator in `[1, 2^255)`, `k·G` |
| base-mul-p | mul-p | `0x5046503250485032` | 4096 | original `scalar_for`, `k·P` with `P = j·G` |
| upper-g | upper-g | `0x5050463232555047` | 4096 | uniform in `[2^255, q−1]`, `k·G` |
| upper-p | upper-p | `0x5050463232555050` | 4096 | uniform in `[2^255, q−1]`, `k·P` with `P = j·G` |
| boundary-g | boundary-g | `0x5050463232424f47` | 8 | fixed scalars as `k·G` |
| boundary-p | boundary-p | `0x5050463232424f50` | 8 | the same fixed scalars as `k·P` |
| exceptional | exceptional | `0x5050463232455845` | 10 | structural cases (below) |
| limb-g | limb-g | `0x50504632324c4d47` | 12 | limb occupancy as `k·G` |
| limb-p | limb-p | `0x50504632324c4d50` | 12 | the same scalars as `k·P` |

**Total: 16,434 cases per subject (32,868 case evaluations, 16,434 point comparisons).**
Machine record: `domain-differential-553e1b8c.json`; per-class digests:
`raw/comparison.tsv`.

## Per-class results

| class | cases | candidate = authority | mismatches | points sha256 (candidate = authority) |
|---|---:|---|---:|---|
| base-mul-g | 4096 | yes | 0 | `a9e1068d9c28846fd8beec36d372845723e9f253f3c09602fe93bfb7a23361fd` |
| base-mul-p | 4096 | yes | 0 | `bcb22a91415f5a8593262b56935218f0a21712b2bbedddb2d8824d485af9e23b` |
| upper-g | 4096 | yes | 0 | `5aa11f7ce28c896d4a44d885d2364874fd7632c925e85fd3981001ab8a1a4c50` |
| upper-p | 4096 | yes | 0 | `e364eb3e41670413725ef7b5a35be13475884e6f91362e73936ed7c0e2a41180` |
| boundary-g | 8 | yes | 0 | `412a0adb3593b02dcdf9aa5034657a6b49bcf2c62e35e48d35eca0f0d5763ad6` |
| boundary-p | 8 | yes | 0 | `7d37a627ba14ba9f58a45a5125ed24e7bc20925d31f1eedeb211b1aa97390d2d` |
| exceptional | 10 | yes | 0 | `07c10828a61883dd69eb4d26c67c9acf888b1f498ed6aa52fa2288e95fa2a013` |
| limb-g | 12 | yes | 0 | `ed46a959522f20d7f90a3894dada1b37a91778f79cdffe849a81f57166f459ed` |
| limb-p | 12 | yes | 0 | `f2d5f0381ad53488d62ee02ed8d02d215dc7672139862020dffd8ce43b880c37` |

### Order boundaries (`raw/boundary-g-authority.points`, identical on the candidate)

The API (`EC_POINT_mul`) does not reject an out-of-range scalar: it accepts an
arbitrary-precision `BIGNUM` and computes the group result. Candidate and authority
therefore agree on the **computed point**, and both reject the one genuinely invalid
input (an off-curve point, below).

| scalar | expected | observed (both) |
|---|---|---|
| `1` | `G` | `04 6b17d1f2…` (generator) |
| `2` | `2G` | `04 7cf27b18…` |
| `q−2` | `−2G` | same x as `2G` (`04 7cf27b18…`) |
| `q−1` | `−G` | same x as `G` (`04 6b17d1f2…`) |
| `q` | infinity | `00` |
| `q+1` | `G` | `04 6b17d1f2…` |
| `2q−1` (33 bytes) | `−G` | same x as `G` (`04 6b17d1f2…`) |
| `2^256−1` | `(2^256−1 mod q)·G` | `04 f72cbd24…` (equals the all-`0xff`-limb case) |

`q−1`, `q`, `q+1`, `2q−1` and `2^256−1` are the boundaries the earlier
below-2^255 population never exercised. `2q−1` does not fit in 32 bytes and is
supplied as a 33-byte BIGNUM; that is recorded, not excluded.

### Exceptional and structural (`raw/exceptional-authority.points`)

| # | case | input | observed (both) |
|---:|---|---|---|
| 0 | `zero_alllimbs_g` | scalar `0` (all-zero limbs), `k·G` | infinity `00` |
| 1 | `zero_alllimbs_p` | scalar `0`, `k·P` | infinity `00` |
| 2 | `allff_limbs_g` | scalar `2^256−1`, `k·G` | `04 f72cbd24…` |
| 3 | `allff_limbs_p` | scalar `2^256−1`, `k·P` | `04 9a024d3e…` |
| 4 | `infinity_base_5` | base infinity, `k = 5` | infinity `00` (API accepts infinity input) |
| 5 | `infinity_base_zero` | base infinity, `k = 0` | infinity `00` |
| 6 | `generator_base_7` | base `G`, `k = 7` | `04 8e533b6f…` |
| 7 | `nongenerator_base_7` | base `P = j·G`, `k = 7` | `04 95192b40…` |
| 8 | `decode_generator_mul7` | `oct2point(G)` then `7·decoded` | accepted; equals case 6 |
| 9 | `reject_offcurve` | `oct2point(04 ‖ 0^64)` | **rejected** on both (`status=rej`) |

**Small-order point:** P-256 has prime group order `n`, so it has **no**
non-trivial small-order point. The only order-1 point is infinity, exercised as an
input base (cases 4–5) and produced by zero scalars (cases 0–1). This is stated
rather than substituted.

### Limb occupancy (`raw/limb-g-authority.points`, `raw/limb-p-authority.points`)

Twelve scalars per base: one non-zero 64-bit limb in each of the four positions with
limb value `1` and `0xffffffffffffffff` (8 cases), and four values whose
most-significant limb is zero (`< 2^192`) (4 cases). All accepted; candidate equals
authority on every serialised point, for both `k·G` and `k·P`.

## Comparability

The original 4096 `k·G` and 4096 `k·P` population at seed `0x5046503250485032`
reproduces the digests recorded at the same two DSOs in
`dso-differential-pfp20/raw`:

- `mul-g` → `a9e1068d9c28846fd8beec36d372845723e9f253f3c09602fe93bfb7a23361fd`
- `mul-p` → `bcb22a91415f5a8593262b56935218f0a21712b2bbedddb2d8824d485af9e23b`

So adding the new classes did not alter the comparable population.

## Scope and limitations

- Internal field operations (`p256::mont_reduce_into`, `p256::wide_mul_x86`,
  `limbs::normalise_branchless`) have no exported entry point and are exercised only
  through `EC_POINT_mul` / `EC_POINT_oct2point`; no source-level test is substituted
  while this court is called DSO-bound.
- `EC_POINT_mul` accepts scalars beyond `q`; "out of range" is therefore a computed
  result, not a rejection, and this record says so. The compared rejection is the
  off-curve point decode.
- The candidate is a frozen DSO, not rebuilt here; its digest is checked before and
  after execution.
- This is a compatibility/correctness court. It is **not** a constant-time result and
  **not** a safety conclusion.

## Reproduce

```
OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
  bash docker/openssl-rs-court.sh exec bash \
    evidence/performance-frontier/campaigns/PFP-2/dso-differential/pfp22-domain-553e1b8c/run_domain.sh
```

The runner refuses (exit 1) on any identity mismatch, population shortfall, base
drift, changed DSO digest, or a single serialised-point difference.
