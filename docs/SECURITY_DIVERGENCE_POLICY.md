# Security Divergence Policy

Status: **constitution** (Phase 0).

Custodianship is not fossilisation of vulnerabilities. When historical OpenSSL
behaviour differs from a security-fixed authority, the fixed behaviour wins for
production, and the historical behaviour becomes a *recorded trajectory*, never a
reintroduced defect.

## 1. The 3.6.3 → 3.6.4 trajectory

Two authorities are admitted:

| authority | role |
|---|---|
| `openssl-3.6.3-historical` | what extant downstream archaeology observed |
| `openssl-3.6.4-production` | the production target (security-fix release) |

Before the production authority is claimed, an **oracle-vs-oracle** differential
court runs 3.6.3 against 3.6.4 over the shared court families, producing an
oracle/oracle residual atlas. This teaches the system what *legitimate upstream
behavioural evolution* looks like, and prevents wasting effort reproducing a
3.6.3 quirk that upstream itself removed.

The trajectory is recorded through the FRF chain
(Authority → Court → Capture → Residual → Endoduction → Route → Disposition →
Receipt → Claim) so that "why does this behaviour exist?" is always answerable.

## 2. Procedure when historical behaviour differs from the fixed authority

1. **Retain** the historical raw observation, unchanged.
2. **Reproduce** the issue in an isolated oracle-only court if needed.
3. **Admit** the fixed OpenSSL authority.
4. **Establish** the oracle-version trajectory.
5. **Implement** the fixed production behaviour.
6. **Disposition** the historical residual as an oracle-version / security
   evolution — a first-class, nameable outcome, not a suppression.
7. **Never** silently claim historical vulnerable behaviour is production parity.

## 3. Prohibited

- Copying a known memory-safety defect merely to obtain byte-level parity.
- Reintroducing a security regression to match a historical authority.
- Silently reproducing known vulnerabilities.
- Suppressing a failing oracle test without proving the oracle fails identically.

## 4. When compatibility and safety genuinely conflict

If exact compatibility and safety conflict, the conflict is **documented
explicitly** and the parity claim is **narrowed**. It is never hidden. A narrowed
claim is an honest result; a hidden conflict is a defect in the evidence.

The narrowing is recorded as a residual with disposition
`intentional_safe_divergence`, naming:

- the exact obligation affected;
- the authority behaviour reproduced or not;
- the security reason;
- the scope removed from the claim.

## 5. Interpretation of "authority" for security-relevant behaviour

An authority is a *behavioural* reference, not a moral one. Where the authority
contains undefined behaviour, the candidate does **not** reproduce the undefined
behaviour merely because one observed run yielded a particular result. Such cases
are recorded as *compatibility boundaries* (see `docs/RELEASE_GATES.md`
§"Safety testing").

## 6. Register of recorded safety divergences

Every entry below was found by running a probe against the authority and observing a fault -- the
Phase 3 entries from `courts/phase3/`, and the Phase 7 ones from `RT-FETCH`'s provider plus, where
the entry says so, a measurement program compiled against the pinned prefix in a process of its own,
because a fault cannot be *compared* and so is measured once and printed as a boundary from then
on. A probe cannot compare a crash, so in
each case the probe prints a `NOT_MEASURED_AUTHORITY_FAULTS` marker: the boundary
is visible in the transcript rather than silently absent from it. The
observations that *can* be made around each boundary are compared normally.

### D-CIPHERCTX-NOALG-1 — `EVP_CIPHER_CTX_gettable_params` dereferences a NULL cipher

- **Obligation:** `EVP_CIPHER_CTX_gettable_params` and its `_settable_` twin, on a context created by
  `EVP_CIPHER_CTX_new()` and not yet initialised.
- **Authority:** **faults.** The guard is
  `if (cctx != NULL && cctx->cipher->gettable_ctx_params != NULL)` (`crypto/evp/evp_enc.c:1730`),
  which dereferences `cctx->cipher` without checking it. Measured: a fresh context segfaults, so the
  condition's own precondition is one the function does not establish.
- **Candidate:** total and quiet. Both accessors test `(*cctx).cipher.is_null()` and answer NULL.
- **Reason:** calling through a NULL pointer is not a contract to reproduce. It is the same class as
  D-LHASH-1 and D-STACK-2, and reproducing it would violate §3's prohibition on copying a known
  memory-safety defect.
- **Claim removed:** none. The boundary cannot be compared — one side dies — so `RT-CIPHER`'s
  `ChaCha20` arm prints `chacha.x.cgp.unset=NOT_MEASURED_AUTHORITY_FAULTS` on both sides and the
  reachable observation, the two lists read *after* an init, is compared normally.

### D-MEM-ALIGNED-1 — the `CRYPTO_aligned_alloc` family writes through a NULL `freeptr`

- **Obligation:** `CRYPTO_aligned_alloc(num, align, NULL, file, line)` and
  `CRYPTO_aligned_alloc_array(num, size, align, NULL, file, line)`.
- **Authority:** segfaults on both. The first statement of each is `*freeptr =
  NULL;` with no test, and the `_array` form reaches it through the overflow arm
  as well. Measured: exit 139 for both, each in a process of its own, so the
  measurement is the fault and there is nothing to compare past it
  (`courts/phase3/rt_mem_default_probe.c` prints the marker).
- **Candidate:** returns NULL. Its own doc comment had said `freeptr` "must be
  NULL or writable for one pointer", which read as though NULL were an accepted
  argument while the authority's code makes it a fault; the code was already safe
  and the *documentation* was the defect.
- **Reason:** a NULL store is not a contract to reproduce. The distinction matters
  more here than for the other entries in this section because the guard is the
  difference between a returned error and a crash in a function whose whole purpose
  is to hand the caller a pointer to release.
- **Claim removed:** NULL-`freeptr` behaviour is *not* claimed compatible; it is
  claimed *safe*. For a writable `freeptr` the value and the block identity are
  compared normally and match.

### D-MEM-ATOMIC-1 — atomics dereference a NULL `ret`

- **Obligation:** `CRYPTO_atomic_or` / `CRYPTO_atomic_and` / `CRYPTO_atomic_load`
  / `CRYPTO_atomic_load_int` / `CRYPTO_atomic_store` with a NULL `ret` (where the
  signature has one).
- **Authority:** segfaults.
- **Candidate:** returns the documented failure value (0) and writes nothing.
- **Reason:** a NULL dereference is not a contract to reproduce.
- **Claim removed:** the behaviour of these entry points under a NULL `ret` is
  *not* claimed compatible; it is claimed *safe*.

### D-EXDATA-1 — `CRYPTO_get_ex_data` / `CRYPTO_set_ex_data` dereference a NULL `CRYPTO_EX_DATA *`

- **Obligation:** both entry points with a NULL `ad`.
- **Authority:** segfaults.
- **Candidate:** `get` returns NULL, `set` returns 0. `CRYPTO_dup_ex_data` with a
  NULL `to`/`from` likewise returns 0.
- **Reason:** as above. Note this is a real hazard, not a theoretical one: the
  authority performs no NULL check at all here.
- **Claim removed:** NULL-`ad` behaviour is not claimed compatible.

### D-SECURE-1 — `CRYPTO_secure_used` before init or after `done`

- **Obligation:** `CRYPTO_secure_used()` when the secure heap is not initialised.
- **Authority:** segfaults (it dereferences the NULL heap pointer rather than
  reporting zero).
- **Candidate:** returns 0.
- **Claim removed:** not claimed compatible.

### D-SECURE-2 — `CRYPTO_secure_actual_size` on a released block

- **Obligation:** `CRYPTO_secure_actual_size(ptr)` after the block was released.
- **Authority:** aborts with an internal assertion
  (`crypto/mem_sec.c`: `(bit & 1) == 0`).
- **Candidate:** returns 0.
- **Claim removed:** not claimed compatible. For a *live* allocation the value is
  compared normally and matches.

### D-LHASH-1 — the `doall` family on a table built by the bare `OPENSSL_LH_new`

- **Obligation:** `OPENSSL_LH_doall`, `OPENSSL_LH_doall_arg`,
  `OPENSSL_LH_doall_arg_thunk` on a table that has not had
  `OPENSSL_LH_set_thunks` called on it.
- **Authority:** segfaults. Every generated `lh_TYPE_new` installs thunks, and the
  iteration entry points dereference the (NULL) thunk rather than falling back to
  direct iteration.
- **Candidate:** iterates the table directly and invokes the caller's function.
- **Reason:** reproducing a NULL call is not a compatibility goal.
- **Claim removed:** the *iteration order* of the authority could not be observed
  in this configuration, so `src/runtime/lhash.rs` makes no order claim. Callers
  that go through the generated `lh_TYPE_*` accessors (the normal path, which does
  install thunks) are unaffected in either implementation.

### D-STACK-1 — `OPENSSL_sk_set_cmp_func` dereferences a NULL stack

- **Obligation:** `OPENSSL_sk_set_cmp_func(NULL, cmp)`.
- **Authority:** segfaults; the function reads `sk->comp` with no NULL check.
- **Candidate:** returns NULL.
- **Claim removed:** not claimed compatible.

### D-STACK-2 — `OPENSSL_sk_pop_free` calls a NULL destructor

- **Obligation:** `OPENSSL_sk_pop_free(st, NULL)` where `st` holds a non-NULL
  element and no thunk has been installed.
- **Authority:** calls through the NULL function pointer. (With a thunk installed
  — the normal path, because every generated `sk_TYPE_new_reserve` installs one —
  the thunk receives the NULL `func` and decides.)
- **Candidate:** leaves the element untouched and frees the stack.
- **Reason:** reproducing a NULL call is not a compatibility goal, and the
  element cannot be freed without a destructor anyway.
- **Claim removed:** the NULL-`func`/no-thunk case is not claimed compatible.
  With a destructor or a thunk the call is compared normally and matches.

### D-STACK-3 — `OPENSSL_sk_deep_copy` calls a NULL copy function

- **Obligation:** `OPENSSL_sk_deep_copy(st, NULL, f)` where `st` holds a non-NULL
  element.
- **Authority:** calls through the NULL copy function.
- **Candidate:** returns NULL. A NULL or empty source is *not* affected: the
  authority never calls the copy function in that case, and both sides return a
  fresh empty stack.
- **Claim removed:** not claimed compatible.

### D-STACK-4 — `OPENSSL_sk_deep_copy(NULL, …)` leaves `free_thunk` uninitialised

- **Obligation:** `OPENSSL_sk_deep_copy(NULL, c, f)`, then using the result in a
  way that consults the thunk.
- **Authority:** reads an uninitialised field. The `sk == NULL` branch sets only
  `num`, `sorted` and `comp`, leaving `free_thunk` as whatever `OPENSSL_malloc`
  returned; the field is then copied by the structure assignment on every
  non-NULL path.
- **Candidate:** stores NULL.
- **Reason:** an uninitialised read is nondeterministic, so no two runs of the
  authority need agree and no probe can compare it. A deterministic value is the
  only reproducible choice.
- **Claim removed:** the thunk observed on a `deep_copy(NULL, …)` result is not
  claimed compatible.

### D-ERR-1 — `ERR_error_string_n` with a NULL buffer

- **Obligation:** `ERR_error_string_n(e, NULL, len)` with a non-zero `len`.
- **Authority:** passes the NULL pointer to its bounded formatter, which
  dereferences it.
- **Candidate:** returns without writing. The installed header documents `buf` as
  the destination, so a NULL there is a caller error either way.
- **Claim removed:** not claimed compatible. `ERR_error_string_n(e, NULL, 0)` is a
  documented no-op in both and *is* compared (the probe calls it).

### D-BIO-ADDR-1 — the `BIO_ADDR` accessors dereference a NULL address

- **Obligation:** `BIO_ADDR_family`, `BIO_ADDR_rawaddress`, `BIO_ADDR_rawport`,
  `BIO_ADDR_clear`, `BIO_ADDR_hostname_string`, `BIO_ADDR_service_string` and
  `BIO_ADDR_path_string` called with `ap == NULL`.
- **Authority:** faults. Each case was measured in **its own process** by
  `courts/phase4/bio_addr_null_calls.c` (a probe cannot compare a crash, and a
  crash in a shared process would hide every later observation), all seven
  exiting 139 = `SIGSEGV`.
- **Candidate:** returns the harmless value — `AF_UNSPEC` for the family, `0` for
  the lengths and the port, no-op for the clear, NULL for the three strings.
- **Reason:** the contract is that `ap` is a live address; the authority does not
  check, and a parity-motivated dereference of NULL would be importing an
  exploitable fault.
- **Claim removed:** not claimed compatible. The **defined** null behaviours
  *are* compared: `BIO_ADDR_free(NULL)` (no-op), `BIO_ADDR_dup(NULL)` (NULL) and
  `BIO_ADDR_copy(NULL, ...)` (`0`) all survive in the authority and are probed by
  `RT-BIO-ADDR`.

### D-BIO-ADDR-2 — `BIO_ADDR_rawmake` dereferences a NULL `where`

- **Obligation:** `BIO_ADDR_rawmake(ap, AF_INET, NULL, 4, 0)`.
- **Authority:** validates the length, then copies from `where`, so it faults.
  Found by `RT-BIO-ADDR`: the authority transcript stopped at the observation just
  before this call, which is how a fault in a shared probe is detected — the
  candidate's later observations appear as `authority=None`.
- **Candidate:** returns `0` without touching `ap`.
- **Reason:** as above; the address and the length are the caller's contract.
- **Claim removed:** not claimed compatible. The *rejection* cases are compared,
  because those are defined: a wrong `wherelen`, `AF_UNSPEC`, an unknown family,
  and an `AF_UNIX` path longer than `sun_path` all return `0` and leave the
  previous address intact in both.

### D-BIO-ADDR-3 — `BIO_ADDR_rawmake` copies from `where` with `strncpy` semantics

- **Obligation:** `BIO_ADDR_rawmake(ap, AF_UNIX, path, wherelen, 0)` where `wherelen`
  is smaller than `strlen(path)`.
- **Authority:** bounds the call with `wherelen + 1 > sizeof(sun_path)` but then
  copies with `strncpy(sun_path, where, sizeof(sun_path) - 1)`, which **ignores
  `wherelen`** and reads up to `strlen(path)` bytes (or 107, whichever is first). A
  caller that declares four readable bytes but passes a longer string has bytes
  beyond that boundary read.
- **Candidate:** reproduces the copy exactly — it is the defined behaviour for a
  valid C string, and the destination is zero-filled first, so the stored path is
  always NUL-terminated. The read is bounded to 107 bytes, as `strncpy`'s `n`
  bounds it. What is *not* reproduced is a caller passing a buffer shorter than the
  string it points at; that is a caller error in both.
- **Claim removed:** no claim is made about a caller whose buffer is shorter than
  the string it passes. `RT-BIO-ADDR` compares the defined cases (`wherelen` 4 with
  a 8-byte string still yields the whole path; 107 is accepted, 108 is refused) and
  a unit test asserts them.

### D-BIO-RESOLVE-1 — the resolver entry points dereference their out-parameters

- **Obligation:** `BIO_lookup_ex(…, res == NULL)`; `BIO_lookup_ex(NULL, …, AF_UNIX,
  …)`; `BIO_parse_hostserv(NULL, …)`; `BIO_get_host_ip(str, NULL)`;
  `BIO_get_port(str, NULL)`.
- **Authority:** faults in each case — `res` is passed to `getaddrinfo`, the AF_UNIX
  path calls `strlen(host)`, `BIO_parse_hostserv` dereferences `hostserv`
  immediately, and the two helpers copy into or assign through their out-parameter.
  Measured for `BIO_parse_hostserv`/`BIO_ADDR` by
  `courts/phase4/bio_addr_null_calls.c` (one call per process); the rest follow
  directly from the pinned source and are *not* probed, because a probe cannot
  compare a crash and these calls are not ambiguous.
- **Candidate:** total. `BIO_lookup_ex` returns `0`; `BIO_parse_hostserv` returns `0`;
  the helpers skip the write and, where the authority would have raised first, the
  raise still happens (`BIO_get_port(NULL, NULL)` raises `BIO_R_NO_PORT_DEFINED`,
  which the authority does before touching `port_ptr`).
- **Reason:** an out-parameter the callee cannot write is a caller error, and
  dereferencing it is an exploitable fault rather than a defined behaviour.
- **Claim removed:** not claimed compatible. Note that `BIO_get_host_ip(NULL, ip)`
  **is** defined and matched: a NULL *host* is legal for the resolver, which returns
  the loopback, and the authority raises and appends `host=<NULL>`.

### D-LHASH-2 — `OPENSSL_LH_stats_bio` and friends dereference a NULL table

- **Obligation:** `OPENSSL_LH_stats_bio(NULL, out)`,
  `OPENSSL_LH_node_stats_bio(NULL, out)`, `OPENSSL_LH_node_usage_stats_bio(NULL,
  out)` and the `FILE *` forms with a NULL table.
- **Authority:** faults. Every one of them reads `lh->num_items` (or `lh->num_nodes`)
  before doing anything else, so the NULL table is dereferenced immediately. Unlike
  `D-LHASH-1` this is not a thunk that a generated accessor would have installed —
  there is no configuration in which a NULL table is readable. Measured directly
  against the authority: `OPENSSL_LH_stats_bio(NULL, b)` segfaults while
  `OPENSSL_LH_stats_bio(lh, NULL)` survives, because the BIO layer's write path
  tolerates a NULL `BIO *` and the table is never reached.
- **Candidate:** total. A NULL table writes nothing and returns, and `RT-LHASH`
  records the boundary as `stats.null_table=NOT_MEASURED_AUTHORITY_FAULTS` rather
  than calling it, because a probe cannot compare a crash.
- **Reason:** a NULL dereference is not a contract to reproduce.
- **Claim removed:** the behaviour of these entry points with a NULL table is not
  claimed compatible; it is claimed *safe*. The NULL-*destination* forms **are**
  matched and compared, and `RT-LHASH` asserts them.

### D-CONF-1 — `CONF_parse_list` calls a NULL callback

- **Obligation:** `CONF_parse_list(list, sep, nospc, NULL, arg)`.
- **Authority:** faults. The walk delivers each element by calling `list_cb`, and
  there is no NULL test, so the first delivery is a call through a NULL function
  pointer. `RT-CONF` measured it: the probe died on the first element, with the
  transcript stopping immediately after `parselist.stop`.
- **Candidate:** total. A NULL callback means "nothing to deliver to", and the
  function returns 0 without walking.
- **Reason:** calling a NULL function pointer is not a contract to reproduce; it is
  the same class as `D-LHASH-1` and `D-STACK-2`.
- **Claim removed:** the behaviour of `CONF_parse_list` with a NULL callback is not
  claimed compatible. `RT-CONF` prints
  `parselist.nocb.value=NOT_MEASURED_AUTHORITY_FAULTS` rather than comparing a
  value, and every other `CONF_parse_list` behaviour — including the empty-element,
  trailing-separator and callback-abort cases — **is** compared.

### D-CONF-2 — `_CONF_new_section` frees an uninitialised field on its error path

- **Obligation:** `_CONF_new_section(conf, section)` when the allocation of
  `v->section` fails.
- **Authority:** the error path is
  ```c
  err:
      sk_CONF_VALUE_free(sk);
      if (v != NULL)
          OPENSSL_free(v->section);
      OPENSSL_free(v);
      return NULL;
  ```
  and `v->section` is only assigned *after* the allocation that just failed, so the
  free is handed the previous contents of freshly `OPENSSL_malloc`ed memory. The
  fault needs an allocation failure to reach, so no court can measure it.
- **Candidate:** frees only what it allocated — the stack if it was created, and the
  entry if it was created.
- **Reason:** freeing uninitialised memory is a defect, and the case is only
  reachable under memory exhaustion, where the authority's behaviour is undefined
  anyway.
- **Claim removed:** the error path of `_CONF_new_section` under allocation failure
  is not claimed compatible. The success path, and the "section already exists"
  path that shares the same error block, **are** compared by `RT-CONF` — the latter
  through `[s1]` appearing twice in the `sections` fixture.

### D-CONF-3 — `CONF_get1_default_config_file` does not claim the forensic `OPENSSLDIR`

- **Obligation:** `CONF_get1_default_config_file()` with `OPENSSL_CONF` unset.
- **Authority:** `OPENSSL_strdup(X509_get_default_cert_area() "/" "openssl.cnf")`,
  where `X509_get_default_cert_area()` is `X509_CERT_AREA` = the build's
  `OPENSSLDIR` = `/work/forensics/authorities/prefix/openssl-3.6.4-production/ssl`
  for the admitted authority.
- **Candidate:** an empty string.
- **Reason:** that path is the *forensic build's installation directory*. This
  implementation is not installed there, and no machine it ships to has that
  directory. `src/runtime/init.rs` already made and recorded this decision for the
  same constant: `OpenSSL_version(OPENSSL_DIR)` answers `OPENSSLDIR: N/A`
  (`OBL-INIT-VERSION-DIRS`) for exactly this reason. The empty string is the
  authority's own idiom for "no such path" — its
  `X509_get_default_cert_area() == NULL` arm returns `OPENSSL_strdup("")` — and
  `CONF_modules_load_file_ex` treats an empty name as "do not load a file" without
  erroring. A unit test asserts the answer is *not* the authority's directory.
- **Claim removed:** the no-`OPENSSL_CONF` branch is not claimed compatible. The
  environment branch **is** compared byte for byte by `RT-CONF`, and the unset
  branch is printed as
  `defaultcfg.unset=RECORDED_DIVERGENCE_OBL_CONF_DEFAULT_CONFIG_FILE` rather than as
  a value. The open obligation is `OBL-CONF-DEFAULT-CONFIG-FILE`, owned by Phase 16.

### D-GF2M-1 — `BN_GF2m_mod_inv` returns the right value without the authority's blinding

- **Obligation:** `BN_GF2m_mod_inv(r, a, p, ctx)` and, through it,
  `BN_GF2m_mod_inv_arr` and the two `BN_GF2m_mod_div*` entry points.
- **Authority:** blinds the inversion. It draws a random field element `b` with
  `BN_priv_rand_ex(b, numbits - 1, …)` (retrying while `b` is zero), computes
  `r := (a*b) * (a*b)^-1 * b = a^-1` through `BN_GF2m_mod_inv_vartime`, and the
  blinding is there so the **timing** of the vartime inversion is not a function of
  `a`.
- **Candidate:** computes the same inverse by extended Euclid over `GF(2)[x]`, without
  the blinding. The **returned value is identical** — the multiplicative inverse in a
  field is unique — and `RT-BN` compares it, both directly and through the identity
  `a * a^-1 == 1`, and against `BN_GF2m_mod_inv_arr`'s separate route.
- **Why:** `BN_priv_rand_ex` is Phase 9 and does not exist. Substituting a non-random
  factor would be worse than omitting it: a fixed "blinding" value is not blinding, and
  a caller cannot tell the difference.
- **Claim removed:** **the timing profile is not claimed to match.** What is claimed is
  that the value, the return class and the error behaviour match, which the court
  measures. A caller that relies on this inversion's timing being input-independent
  under the authority must not rely on it here. The obligation is
  `OBL-GF2M-INV-BLINDING`, owned by Phase 9, and it closes by adding the blinding when
  RAND exists.

### D-GF2M-2 — the `BN_GF2m_*` arithmetic is not the authority's carry chains

- **Obligation:** the fifteen `BN_GF2m_*` entry points.
- **Authority:** unrolled word-at-a-time carry chains written for speed.
- **Candidate:** the same operations written as field arithmetic — carry-less
  multiply, shift-and-xor reduction, extended Euclid — with no unrolling.
- **Reason:** the value in `GF(2)[x]/(p)` has exactly one canonical representative, so
  both routes reach it; what differs is the machine code and therefore the timing.
  Reproducing the carry chains would reproduce a *performance* property, not a
  behavioural one, and a mistranscribed carry chain is a wrong answer rather than a
  slow one.
- **Claim removed:** **no timing claim** about these functions, in either direction.
  The values, return classes and error behaviour are compared by `RT-BN`, including
  that the `_arr` and non-`_arr` routes agree with each other and that
  `BN_GF2m_mod_inv`'s result satisfies `a * a^-1 == 1`.

### D-GENCB-1 — `BN_GENCB_call` on a `ver == 2` object whose callback is NULL

- **Obligation:** `BN_GENCB_set(cb, NULL, arg)` followed by `BN_GENCB_call(cb, a, b)`.
- **Authority:** reaches `return cb->cb.cb_2(a, b, cb);` with `cb_2 == NULL` and calls
  through a null pointer. `BN_GENCB_set` stores the NULL without checking it and sets
  `ver = 2` unconditionally, so no earlier call rejects the object.
- **Candidate:** answers `0`, the value the authority's own `default` arm returns for a
  callback type it does not recognise.
- **Reason:** a null call is a fault, not a behaviour a caller can depend on, and
  reproducing it would be reproducing a crash. `0` is chosen rather than `1` because a
  caller that reaches this state has no callback that ran, and `1` would tell a
  generation loop to continue on the strength of nothing.
- **Claim removed:** this one case is not claimed compatible. Every case where a
  callback is actually installed is compared by `RT-BN` and matches, including
  `ver == 1` with a NULL callback, which the authority answers `1` and the candidate
  does too.

### D-GENCB-2 — `BN_GENCB_get_arg` dereferences a NULL `BN_GENCB *`

- **Obligation:** `BN_GENCB_get_arg(NULL)`.
- **Authority:** `return cb->arg;` with no NULL check, so the call faults.
- **Candidate:** answers NULL.
- **Claim removed:** not claimed compatible. The probe does not exercise it, because a
  probe cannot compare a crash.

### D-TIME-1 — the time family dereferences its string and its `struct tm` without a test

- **Obligation:** `ossl_asn1_time_to_tm`, the two `_check` functions, the four printers and
  the four constructors, given a NULL time string; `ossl_asn1_time_from_tm` given a NULL
  `struct tm *`; `ASN1_TIME_to_tm(NULL, NULL)`; `OPENSSL_gmtime_diff` given a NULL `from`
  or `to`.
- **Authority:** the ASN.1 string argument is dereferenced through `d->type` and `t->length`
  before any check, the output `struct tm` is dereferenced by `memset` and then by the
  field writes, and `OPENSSL_gmtime_diff`'s `julian_adj` dereferences both inputs. Each call
  faults.
- **Candidate:** answers the function's documented failure value — `0` for the parsers, the
  printers and the comparisons, NULL for the constructors.
- **Claim removed:** not claimed compatible. The probe does not exercise these, because a
  probe cannot compare a crash.

### D-TIME-2 — the calendar arithmetic wraps instead of being undefined on overflow

- **Obligation:** `OPENSSL_gmtime_adj(tm, off_day, offset_sec)` with an `offset_sec` at or
  near `LONG_MIN`/`LONG_MAX`, and `OPENSSL_gmtime_diff` on a `struct tm` whose `tm_year`
  is far outside the range a parsed time can produce.
- **Authority:** `julian_adj`'s `long` arithmetic and `date_to_julian`'s `int` intermediates
  overflow, which is undefined behaviour; the emitted code wraps, but nothing requires it
  to.
- **Candidate:** every operation in `src/runtime/time.rs` is a `wrapping_*` operation, so the
  answer for such an input is *a* value rather than a panic. The crate builds with
  `overflow-checks = true`, so without the wrapping operations a caller could abort the
  process with a panic — which is a strictly worse outcome than an arbitrary value.
- **Claim removed:** no probe compares this region, and no answer there is claimed to match.

### D-MIME-1 — `i2d_ASN1_bio_stream`'s unwind loop does not terminate on a detached stream BIO

- **Obligation:** `i2d_ASN1_bio_stream(out, val, in, SMIME_STREAM, it)` over an item
  whose `ASN1_OP_STREAM_PRE` callback answers a BIO that is *not* in the chain leading
  back to the caller's `out` — for example a freshly allocated `BIO_s_mem()`.
- **Authority:** the unwind is `do { tbio = BIO_pop(bio); BIO_free(bio); bio = tbio; }
  while (bio != out);`. `BIO_pop` answers NULL once the chain ends, and
  `BIO_pop(NULL)`/`BIO_free(NULL)` both return quietly, so `bio` stays NULL and the
  comparison against `out` is never satisfied. The call never returns and consumes
  no memory. Measured: the RT-ASN1-MIME probe was written with exactly such a callback
  first, and the authority run had to be killed by the harness timeout.
- **Candidate:** the loop also stops when `BIO_pop` answers NULL, so the call returns
  the value the copy produced.
- **Claim removed:** not claimed compatible. The divergence is deliberately *not*
  observable through any correct caller, because `BIO_new_NDEF` pushes the filter onto
  `out` before invoking the callback, making `sarg->out` the natural answer for
  `ndef_bio`; the probe's item answers `sarg->out` and the two sides agree byte for
  byte. The record exists because the two implementations differ in the region where
  the authority does not terminate, and an unbounded loop is treated as a fault rather
  than as behaviour to reproduce, exactly as the crashes in this document are.

### D-PEM-1 — `PEM_dek_info` converts a negative remainder to `size_t`

- **Obligation:** `PEM_dek_info(buf, type, len, str)` and `PEM_proc_type(buf, type)`
  over a `buf` whose existing content leaves less room than the text still to be
  written, and `type` longer than the room left.
- **Authority:** the remaining room is an `int` and is converted to `size_t` at each
  `BIO_snprintf` with no test for a negative remainder. `PEM_proc_type` reaches it
  when the caller's prefix already exceeds `PEM_BUFSIZE`. `PEM_dek_info` reaches it
  one step later: `%02X` answers `2` whether or not two bytes were written, so with
  exactly one byte of room left it writes the terminating NUL alone, leaves `j` at
  `-1`, and the *next* iteration calls `BIO_snprintf` with a length of
  `(size_t)-1` and writes the encoding of every remaining byte past the end of the
  caller's buffer.
- **Candidate:** clamps the length to zero at every call and stops the per-byte loop
  when no room remains. Everything inside the buffer is identical — the truncated NULs
  land in the same places, which `RT-PEM`'s near-full-buffer cases measure — so the
  divergence is only in the region the authority writes illegally.
- **Claim removed:** the region is not claimed. The probe deliberately stops one
  arrangement short of it — one byte of room with a second byte still to encode —
  because asking the authority for that answer would smash its own stack frame.

### D-PRINT-1 — `ASN1_item_print` dereferences a NULL `ASN1_ITEM`

- **Obligation:** `ASN1_item_print(out, val, indent, NULL, pctx)` and any interior call
  reached with a NULL item, which a caller can produce by passing a template array whose
  `item` slot is null.
- **Authority:** `ASN1_item_print` reads `it->sname` before any check, and
  `asn1_item_print_ctx` reads `it->funcs`, `it->itype` and `it->utype` immediately, so
  every one of these faults.
- **Candidate:** takes the item as a non-null caller contract, documented in the
  function's `# Safety` section, and dereferences it through a `&Asn1Item`. A null item is
  therefore the caller's error rather than a reproduced fault. A *malformed* item — a
  `templates` pointer that does not describe `tcount` entries, or an `item` slot that is not
  an `ASN1_ITEM_EXP` — is the same class and is equally unreproduced.
- **Claim removed:** not claimed compatible. The probe does not exercise these, because a
  probe cannot compare a crash.

### D-BIOCORE-1 — `BIO_new_from_core_bio` calls a NULL `BIO_up_ref`

- **Obligation:** `BIO_new_from_core_bio(libctx, corebio)` where the context's dispatch
  table supplies `BIO_read_ex` and/or `BIO_write_ex` but **no** `BIO_up_ref`.
- **Authority:** the constructor's guard tests only the two I/O callbacks, and the next
  statement is
  ```c
  if (!bcgbl->c_bio_up_ref(corebio)) { BIO_free(outbio); return NULL; }
  ```
  with no test for `c_bio_up_ref == NULL`. Measured: the guard passes, a BIO is created,
  and the unguarded call jumps to address zero. A table with only one of `read_ex` and
  `write_ex` is therefore accepted by the *guard* and fatal by the *next line*.
- **Candidate:** answers the documented failure instead. The `up_ref` slot is an
  `Option<fn>`, so absence is representable; a missing `up_ref` releases the wrapper BIO
  it just created and returns NULL, exactly as an `up_ref` that answers 0 does. This is
  the same reachable failure a caller who supplied a refusing `up_ref` sees, which is
  why it can be answered rather than reproduced.
- **Reason:** `docs/UNSAFE.md` §5 — a crash is not reproduced merely because an observed
  run produced one. No caller that supplies a usable table can tell the two behaviours
  apart, because every path that reaches the unguarded call in the authority dies there.
- **Claim removed:** a table without `BIO_up_ref` is not claimed to produce a BIO.
  `RT-BIO-CORE` stops one step short: it supplies a table that has `up_ref` and *refuses*
  (`noup.bio=NULL`, and the wrapper's `BIO_free` callback runs with a NULL handle), which
  the authority answers without faulting and which is compared.

### D-BIOCORE-2 — `bio_core_free` calls a NULL `BIO_free`

- **Obligation:** releasing any core BIO whose context has no `BIO_free` callback —
  which includes every BIO built as `BIO_new(BIO_s_core())`, since no export installs a
  table on the default context.
- **Authority:** `bio_core_free` tests only the globals block, then calls
  `bcgbl->c_bio_free(BIO_get_data(bio))` with no NULL test on the stored pointer. The
  globals block is non-NULL for every context (`context_init` fills slot 17 eagerly), so
  the first test never fires and the second call is unguarded.
- **Candidate:** answers `0` from the destroy operation when the callback is absent, and
  lets `BIO_free` proceed to release the wrapper. `0` from `destroy` is not observable
  through `BIO_free`, whose return value reports the reference count rather than the
  destroy result.
- **Reason:** as D-BIOCORE-1.
- **Claim removed:** `BIO_free` of a core BIO whose context supplied no `BIO_free`
  callback is not claimed compatible. `RT-BIO-CORE` frees only BIOs whose tables supply
  `free` (`full`, `wonly`, `ronly`, `noup`, `alpha`, `beta`), and deliberately does not
  free the `plain.bio` it builds with `BIO_new(BIO_s_core())`.

### D-BIOCORE-3 — `ossl_bio_init_core` dereferences a NULL dispatch table

- **Obligation:** `OSSL_LIB_CTX_new_from_dispatch(handle, NULL)` — reachable from an
  export, since the export forwards its `in` argument straight to `ossl_bio_init_core`.
- **Authority:** the table walk's own loop condition is `fns->function_id != 0`, evaluated
  before any NULL test (there is no NULL test anywhere in the function), so a NULL table
  faults on the first iteration.
- **Candidate:** treats NULL as the terminator-only table it is equivalent to and answers
  `1`, so the caller receives an empty but usable context. A table consisting solely of
  `OSSL_DISPATCH_END` reaches the same state in the authority without faulting, and the
  candidate's two paths are indistinguishable from the caller's side.
- **Reason:** `docs/UNSAFE.md` §5. The parameter is documented as a table; the authority's
  own providers never pass NULL.
- **Claim removed:** `OSSL_LIB_CTX_new_from_dispatch(handle, NULL)` is not claimed
  compatible. `RT-BIO-CORE` passes a real table to that export and a NULL *handle*, which
  the authority accepts and ignores.

### D-OSSL-CORE-BIO-1 — `ossl_core_bio_up_ref` dereferences a NULL handle

- **Obligation:** `ossl_core_bio_up_ref` — reachable from a provider, because
  `core_dispatch` publishes it as `OSSL_FUNC_BIO_UP_REF` and a provider may call what the
  core gives it.
- **Authority:** the whole body is `return CRYPTO_UP_REF(&cb->ref_cnt, &ref);` with no NULL
  test, so a NULL handle dereferences NULL. `ossl_core_bio_free`, in the same file and on
  the same type, **is** NULL-tolerant and answers 1 — the asymmetry is the authority's and
  is not explained by anything in the source.
- **Candidate:** answers `0` for a NULL handle. `0` is not a defined answer either — it is
  the value the authority would return for a reference count that has already reached zero —
  so the caller's behaviour on this path is the same as the authority's would be *if* the
  fault did not happen.
- **Reason:** `docs/UNSAFE.md` §5. No caller in the authority passes NULL: the only ones are
  the two constructors, which pass a handle they just built, and `core_dispatch`'s thunk,
  which receives whatever a provider supplies.
- **Claim removed:** `ossl_core_bio_up_ref(NULL)` is not claimed compatible. `RT-PROVIDER`
  does not call it with NULL, and this function has no exported symbol, so it is reachable
  only through the dispatch table a provider is handed.

### D-TEVENT-REENTRANT-1 — a thread-stop handler that registers another handler deadlocks upstream

- **Obligation:** `ossl_init_thread_start`, reachable from a provider through
  `core_dispatch`'s `OSSL_FUNC_CORE_THREAD_START` entry (id 3), which is what
  `ossl_provider_init`'s `in` table hands a provider.
- **Authority:** `init_thread_stop` takes the global register's **write lock** and then calls
  the handler *while holding it*. A handler that calls `ossl_init_thread_start` re-enters
  `init_thread_push_handlers`, which asks for the same lock. On the admitted pthread profile
  the register's lock is a `pthread_rwlock_t`, and `pthread_rwlock_wrlock` on a lock the
  calling thread already holds for writing does not return — the handler never finishes, the
  lock is never released, and thread teardown hangs. Measured by this crate's own lock, which
  refuses a same-thread write acquisition instead of deadlocking: the nested registration is
  answered 0.
- **Candidate:** the nested registration is **refused** with `0`, and the handler's node is
  released rather than left on a list nobody can walk. The caller observes a failed
  registration and can retry from outside the stop; the alternative is a hang.
- **Reason:** `docs/UNSAFE.md` §5. A deadlock inside thread teardown is not a behaviour a
  consumer can depend on — there is no return value, no error queue entry and no way to
  recover — so reproducing it would be importing a hang for the sake of fidelity.
- **Claim removed:** "a handler may register another handler during a stop" is not claimed
  compatible. Unit test `a_handler_registered_during_a_stop_is_refused` asserts the refusal,
  and the *certain* half — that the nested handler is not called by the same stop, because the
  walk unlinks as it goes — is asserted with it.

### D-CHILD-DEREGISTER-NULL-1 — `ossl_provider_init_as_child` does not validate one pointer, and `ossl_provider_deinit_child` calls it unguarded

- **Obligation:** `ossl_provider_init_as_child` and `ossl_provider_deinit_child`,
  `crypto/provider_child.c`. Reachable from `OSSL_LIB_CTX_new_child` and
  `OSSL_LIB_CTX_free`, so any third-party provider that creates a child context is on both
  paths.
- **Authority:** the initialiser stores **eight** dispatch entries and validates **seven** —
  `c_get_libctx`, `c_provider_register_child_cb`, `c_prov_name`,
  `c_prov_get0_provider_ctx`, `c_prov_get0_dispatch`, `c_prov_up_ref` and `c_prov_free`. The
  eighth, `c_provider_deregister_child_cb`, is not in the test. Then
  `ossl_provider_deinit_child` calls `gbl->c_provider_deregister_child_cb(gbl->handle)`
  **unguarded**, so a parent that publishes a table without `OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB`
  initialises successfully and **jumps through NULL** when the context is freed.
- **Candidate:** the initialisation half is the authority's **exactly** — seven validated, the
  eighth stored unvalidated — so a court comparing the initialisation contract sees the
  authority. The teardown half **checks the pointer and returns when it is absent**.
- **Reason:** a jump through NULL inside `OSSL_LIB_CTX_free` is a fault, and faults are
  recorded rather than reproduced (`docs/UNSAFE.md` §5). Splitting the pair is the point: the
  *validation contract* is observable and is claimed, and the *fault* is not.
- **Claim removed:** "a child context created from a table without the deregister entry cannot
  be freed" is not claimed. The candidate can free it; the authority cannot.
- **Observed how:** `RT-LIBCTX` creates a child with the seven-entry table and observes the
  initialisation succeeding (`child.no_deregister=nonnull`,
  `child.no_deregister.register_called=1`), and **deliberately does not free it** — freeing it
  would crash the authority, so the divergence's teardown half is stated in the probe's own
  comment rather than measured.

### D-CHILD-REGISTER-PROPS-1 and D-CHILD-PROPS-CB-1 — the child's global-property path, which is Phase 7's

These two are one divergence with two halves, and they are the reason the child mechanism is
complete in this crate without being complete in the authority. Both are the same missing
function: `crypto/evp/evp_fetch.c`'s `evp_get_global_properties_str` and
`evp_set_default_properties_int`, which are **Phase 7's** and are recorded deferrals in
`forensics/prerequisites.json`.

- **Obligation:** `provider_global_props_cb` (`crypto/provider_child.c`) and
  `ossl_provider_register_child_cb` (`crypto/provider_core.c`'s, reached through the core
  dispatch entry `OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB`).
- **Authority:** `provider_global_props_cb` is `evp_set_default_properties_int(ctx, props, 0,
  1)` and answers its result. `ossl_provider_register_child_cb` calls `propsstr =
  evp_get_global_properties_str(libctx, 0)` and, when it is non-NULL, calls the registrant's
  `global_props_cb(propsstr, cbdata)` **before** the walk over the store's providers.
- **Candidate:** `provider_global_props_cb` answers **0** — the authority's own failure
  answer — and raises nothing. `ossl_provider_register_child_cb` omits the property-string
  step, so a registering parent is not handed its own global properties at registration time.
- **Reason:** the functions are in a file this stratum does not own and cannot write, and the
  gate records them as owed to Phase 7. Writing a body that quietly answered a value the
  authority would compute differently is exactly what a recorded divergence exists to avoid.
- **Claim removed:** "the child's default property query is initialised from the parent's at
  registration" is not claimed. It becomes claimable in Phase 7.
- **Observed as of 6.12, and on one side only:** `RT-PROVIDER-3P` compiles an
  `OSSL_provider_init` into its own binary, so it is a real third-party provider and it takes
  the parent role. Its registration **succeeds on both sides** — `child.register_child_ret`
  is 2 (the child's own registration plus the probe's) and the probe's `create_cb` runs once
  for the provider it loaded, with the handle equal to the `OSSL_PROVIDER *` the probe's own
  `OSSL_PROVIDER_load_ex` returned. What the court does **not** observe is
  `global_props_cb`: the walk over the store's providers is the authority's and the candidate's
  alike, and it is only the property-string step *before* it that is missing here, so a probe
  that counted `global_props_cb` calls would be counting the divergence rather than the
  contract. The probe stores the callback, reports its pointer as non-NULL — which both sides
  agree on — and does not report whether it was called. The absence of that step is therefore
  still **not measured by any court**, and this entry is what says so.

### ~~D-TEVENT-CTX-STOP-LEAK-1~~ — **WITHDRAWN: the authority does not do this**

**This entry is retained, struck through, because it was wrong and the way it was wrong is
worth reading. It is not a divergence: there is no behavioural difference between the
authority and the candidate for this function, and there was never supposed to be one.**

- **What was claimed:** that the authority's `ossl_ctx_thread_stop` is
  `hands = clear_thread_local(ctx); init_thread_stop(ctx, hands); OPENSSL_free(hands);`, so the
  head is released while other contexts' handler nodes are still linked to it, those nodes leak,
  and a subsequent `OPENSSL_thread_stop` runs nothing.
- **What the authority actually is:**
  `void ossl_ctx_thread_stop(OSSL_LIB_CTX *ctx) { if (destructor_key.sane != -1) {
  THREAD_EVENT_HANDLER **hands = fetch_thread_local(ctx); init_thread_stop(ctx, hands); } }`
  — `fetch_thread_local`, which is `manage_thread_local(ctx, 0, 1)`, fetches **without**
  allocating and **without** clearing; the head is neither cleared nor released, the thread
  keeps it, the register keeps it, and every handler for another context is still reachable.
  `fetch_thread_local` is marked `ossl_unused` in the source because the FIPS build does not
  call it; this profile is the non-FIPS build, which does.
- **How the error survived:** the crate had been written against `clear_thread_local` and a
  `CRYPTO_free` of the head, this test asserted that shape, and the entry was written from the
  test rather than from the authority. A divergence record derived from the candidate's own
  behaviour is a record of nothing, and that is the lesson worth keeping here.
- **Why it became visible:** leaving a freed head's address in `GLOBAL_TEVENT_REGISTER`'s
  `skhands` means the walk in `init_thread_deregister(NULL, 1)`, which `OPENSSL_cleanup` runs,
  dereferences released memory. The Rust build refuses that dereference instead of reading the
  corpse, so the observable was `OPENSSL_cleanup` **aborting the process at exit** — found by
  running the full unit-test binary once the exit-time cleanup was reachable, which it had not
  been before.
- **Candidate now:** the authority's two statements, and no `CRYPTO_free`. Unit tests
  `the_context_stop_filters_on_the_argument` (a survivor is still reachable afterwards) and
  `a_second_context_stop_for_the_same_argument_runs_nothing` (the node that ran is gone) pin
  both halves.
- **Claim removed:** none; the claim is now made and true. See `docs/DECISIONS.md` D127.

### D-RCU-1 — the read side indexes `thread_qps[-1]` when the array is full

- **Obligation:** an eleventh *distinct* `CRYPTO_RCU_LOCK` held simultaneously by one
  thread. `MAX_QPS` is 10 and each slot holds one lock.
- **Authority:** `ossl_rcu_read_lock` scans the ten slots for a free one, and then, for the
  case where every slot is taken:
  ```c
  assert(available_qp != -1);
  data->thread_qps[available_qp].qp = get_hold_current_qp(lock);
  ```
  `NDEBUG` is defined in the admitted profile, so the `assert` is `((void)0)` and
  `available_qp` is still `-1`: the three writes that follow go to `thread_qps[-1]`, which
  is the twelve bytes immediately before the array inside the `rcu_thr_data` allocation.
- **Candidate:** answers `0` — "the hold was refused" — which the function's other two
  failure arms already use for "no data block" and "the thread handler could not be
  registered". A caller that checks the result, as the only in-tree caller will have to
  because it can already be told 0 for two other reasons, sees a refusal instead of a
  corruption.
- **Reason:** out-of-bounds writes are precisely what `docs/UNSAFE.md` §5 refuses to
  reproduce, and the value written would be a lock pointer and two integers written over
  whatever the allocator put there.
- **Claim removed:** eleven simultaneous distinct RCU locks on one thread are not claimed
  compatible. No probe can reach this: it needs eleven live locks from a consumer, and RCU
  has no exported entry point at all (see D-RCU-4). The unit test
  `an_eleventh_distinct_lock_is_refused_rather_than_indexed_out_of_bounds` pins the refusal
  on the candidate side only.

### D-RCU-2 — `ossl_rcu_read_unlock` dereferences a NULL `rcu_thr_data`

- **Obligation:** `ossl_rcu_read_unlock(lock)` on a lock this thread has never read-locked,
  with no thread data for the lock's context.
- **Authority:** the function's first two statements are
  ```c
  struct rcu_thr_data *data = CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, lock->ctx);
  assert(data != NULL);
  ```
  and the `assert` is compiled out under `NDEBUG`, so the loop that follows dereferences
  NULL on its first iteration.
- **Candidate:** returns. "Unlocking something not held" has no defined answer in the
  authority either, so there is nothing to be compatible *with*; the crate declines to
  fault.
- **Reason:** as D-RCU-1.
- **Claim removed:** an unbalanced unlock with no thread data is not claimed compatible.
  `an_unbalanced_unlock_neither_faults_nor_disturbs_a_later_hold` pins that the candidate's
  answer leaves the surrounding state alone, which is the only property that can be stated.

### D-RCU-3 — the read side dies on an over-unlock where the check *is* active

- **Obligation:** an unlock that takes a quiescent point's reader count below zero — more
  unlocks than locks on one lock from one thread.
- **Authority:** the decrement is
  ```c
  ret = ATOMIC_SUB_FETCH(&data->thread_qps[i].qp->users, (uint64_t)1, __ATOMIC_RELEASE);
  OPENSSL_assert(ret != UINT64_MAX);
  ```
  and `OPENSSL_assert` in `include/openssl/crypto.h.in` is **not** `NDEBUG`-gated: it is
  `OPENSSL_die("assertion failed: " #e, ...)`. Measured: the count wrapping to
  `UINT64_MAX` aborts the process. Note the asymmetry with D-RCU-2, and that it is the
  reason this entry exists separately: the authority checks this case and not the other,
  and the crate answers both.
- **Candidate:** puts the count back to zero — the state a caller who never took the hold
  describes — and clears the slot. Leaving the wrapped count in place would make every
  later `ossl_synchronize_rcu` on that lock spin forever, since nothing else can bring a
  count of `UINT64_MAX` down. The slot clearing is what the authority would have done had
  it survived; the restore is the smallest addition that keeps retirement live.
- **Reason:** `OPENSSL_die` is `abort(3)`; a library aborting its caller's process is what
  `docs/UNSAFE.md` §3 says must not happen, and the crate's whole FFI boundary exists to
  convert a defect into a documented failure value.
- **Claim removed:** an over-unlock is not claimed compatible. It is unreachable through the
  crate's own bookkeeping — a `thread_qp` slot is per thread, so only the thread that took
  the hold can reach the decrement — which is why the only evidence is the unit test's
  assertion that the *balanced* path is what reaches the count at all.

### D-RCU-4 — the RCU layer has no C-visible entry point, so it cannot be courted

- **Obligation:** every `ossl_rcu_*` function and `ossl_synchronize_rcu`.
- **Authority:** the whole family is declared in `include/internal/rcu.h`, which is a
  non-installed header; nothing in the 6,499 exports resolves to any of the twelve names,
  and `crypto/conf/conf_mod.c` is the only translation unit in the build that calls them.
- **Consequence:** there is no way to write a differential court for RCU today. A probe
  compares an authority object against a candidate object across the exported surface, and
  RCU is not on it; the only reachable path is `CONF_modules_load`, whose registry the RCU
  lock protects, and that export is still a scaffold (6.10b).
- **What stands in its place:** the twelve functions' evidence is (a) this transcription,
  reviewed against `crypto/threads_pthread.c` order for order and memory-order for
  memory-order, (b) ten unit tests in `src/runtime/rcu.rs`, of which two spawn threads —
  one pinning that a reader on another thread holds retirement off, the other that the
  per-thread data survives a thread stop and is rebuilt on the next hold, which is D118's
  chain end to end. This is **weaker** than a court and it is recorded rather than glossed:
  RCU is `IMPLEMENTED` in `docs/PARITY_MODEL.md`'s terms and it is **not** `PARITY_VERIFIED`.
- **When it changes:** `RT-CONF-MOD` (6.10b) is the court that exercises it end to end, and
  this entry's consequence narrows to "courted only through its consumer" at that point.

### D-NAMEMAP-DOALL-1 — `ossl_namemap_doall_names` calls its visitor without a NULL test

- **Obligation:** `ossl_namemap_doall_names`, and the two `evp_names_do_all` wrappers that
  forward a caller's visitor straight to it.
- **Authority:** `crypto/core_namemap.c` reaches `fn(sk_OPENSSL_STRING_value(names, i), data)`
  with no test, so a NULL visitor is an indirect call through a null pointer. `EVP_CIPHER_names_do_all`
  and `EVP_MD_names_do_all` pass a consumer's pointer through unchanged, and 7.3b makes the first
  of those reachable from a probe, so the fault is no longer only theoretical.
- **Crate:** answers 0 for a NULL visitor. Returning rather than faulting is the same choice
  `docs/UNSAFE.md` §3 records for every other null-callback case, and it is safe *because* the
  visitor is a `const`-qualified function pointer a caller supplies: a NULL one is a caller's
  error, and an error is not a reason to take the caller's process down.
- **Claim removed:** `EVP_CIPHER_names_do_all(cipher, NULL, data)` is not claimed compatible with
  the authority. It is claimed *safe*; the authority's behaviour is a fault and
  `RT-EVP-CIPHER` does not reproduce it — the probe passes a real visitor.
- **Measured, not assumed:** the return value of this function was **also** wrong until
  `RT-EVP-CIPHER` read it. The authority's last line is `return i > 0;` — a presence answer — and
  the crate returned `i`, the count. Every caller before 7.3b tested the result for zero, so the
  two agreed for four phases; the first caller that *returns* the value to a consumer
  (`EVP_CIPHER_names_do_all`) observed `2` against the authority's `1`. That is fixed in the same
  commit, with the unit test that had encoded the wrong semantics corrected rather than deleted.

### D-CIPHERCTX-PARAMS-NULL — the two context-parameter list accessors dereference a NULL cipher

- **Obligation:** `EVP_CIPHER_CTX_gettable_params` and `EVP_CIPHER_CTX_settable_params`.
- **Authority:** both evaluate `cctx->cipher->gettable_ctx_params` (respectively
  `settable_ctx_params`) behind a `cctx != NULL` test **only**. On a context that has never been
  armed — which is the state every caller is in before its first `EVP_CipherInit` — `cipher` is
  NULL and the read is a null-pointer dereference. `RT-EVP-CIPHER` measured it: the authority's
  probe died at the first of the two calls, on a context `EVP_CIPHER_CTX_new` had just made.
- **Crate:** answers NULL for a NULL cipher and asks the provider otherwise. The same choice
  `D-NAMEMAP-DOALL-1` records, for the same reason: a NULL argument is a caller's error, and an
  error is not a reason to take the caller's process down.
- **Claim removed:** `EVP_CIPHER_CTX_gettable_params` and `_settable_params` on an **unarmed**
  context are not claimed compatible. They are claimed *safe*, and the probe observes both where
  the authority can answer — on an armed context, where the authority's own test is satisfied.

### D-MD-NULL-CALLBACK-1 — `evp_md_init_internal` and `EVP_DigestFinal_ex` call through a NULL
### method callback

- **Obligation:** three calls in `crypto/evp/digest.c`, on two different kinds of method.
  - `digest->init` — `evp_md_init_internal`'s legacy arm ends `return ctx->digest->init(ctx);`
    with no test, and a method built by `EVP_MD_meth_new` that never had
    `EVP_MD_meth_set_init` called has a NULL `init`.
  - `digest->final` — `EVP_DigestFinal_ex`'s legacy arm calls `ctx->digest->final(ctx, md)`
    with no test, for a method with `init` set and `final` unset.
  - `digest->newctx` — `evp_md_init_internal`'s provider arm calls
    `ctx->digest->newctx(ossl_provider_ctx(type->prov))` with no test, and a provider that
    publishes only `OSSL_FUNC_DIGEST_DIGEST` (which `evp_md_from_algorithm` accepts: a
    structural count of zero is legal when the standalone one-shot is present) has a NULL
    `newctx`, because the count is what decides whether any of the six structural functions is
    filled.
- **Authority:** **measured**. Three programs, each compiled against
  `forensics/authorities/prefix/openssl-3.6.4-production` and each run in a process of its own,
  print the observations around the call and then die:
  - `EVP_MD_meth_new(NID_undef, NID_undef)` then `EVP_DigestInit_ex(ctx, md, NULL)` —
    `built=1 ctx=1` then **exit 139** (SIGSEGV);
  - the same with `EVP_MD_meth_set_init` called first — `set_init=1`, `init=1`,
    `cmp_final_is_null=1`, then **exit 139** at `EVP_DigestFinal_ex`;
  - `OSSL_PROVIDER_add_builtin` + `OSSL_PROVIDER_load` + `EVP_MD_fetch` of a one-shot-only
    digest, then `EVP_DigestInit_ex(ctx, md, NULL)` — `add_builtin=1 load=1 fetch=1`, then
    **exit 139**.

  In each case the fault is the measurement, so there is nothing to compare past it.
  `RT-FETCH` prints `NOT_MEASURED_AUTHORITY_FAULTS` at each of the three boundaries, so the
  boundary is visible in the transcript rather than silently absent from it.
- **Crate:** answers 0 for each, and raises **nothing**, because the authority raises nothing on
  these paths — it does not return. For the `init` and `final` refusals the context is left as it
  was found, so a caller that catches the 0 can set the missing callback and try again; that is
  the one place this crate's behaviour is *more* usable than the authority's, and it is the
  smallest divergence available rather than a designed kindness.
- **Reason:** an indirect call through a null pointer is not a contract to reproduce. The
  distinction matters more here than for the other entries in this section because all three are
  reached through documented, non-deprecated entry points — `EVP_DigestInit_ex` and `EVP_Digest`,
  both of which a legacy consumer is expected to call — rather than through an argument a caller
  would have to pass deliberately.
- **Claim removed:** the behaviour of `EVP_DigestInit_ex`, `EVP_DigestInit`, `EVP_DigestInit_ex2`
  and `EVP_Digest` on a hand-built method with no `init`, of `EVP_DigestFinal_ex` and
  `EVP_DigestFinal` on one with no `final`, and of any initialise on a provider method with no
  `newctx`, is *not* claimed compatible. It is claimed *safe*.
- **When it changes:** it does not. The authority's behaviour is a fault in 3.6.3 and 3.6.4
  alike; the boundary is permanent and the claim stays narrowed.

### D-MD-DOALL-NULL-1 — `EVP_MD_do_all_provided` calls a NULL visitor

- **Obligation:** `EVP_MD_do_all_provided(libctx, NULL, arg)`.
- **Authority:** **measured**. `evp_generic_do_all` passes the visitor to
  `crypto/evp/evp_fetch.c`'s `filter_on_operation_id`, which calls
  `((*data).user_fn)(method, (*data).user_arg)` for every method whose operation id matches, with
  no test on the pointer. A program that registers a builtin provider, loads it, and then calls
  `EVP_MD_do_all_provided(ctx, NULL, NULL)` prints `add_builtin=1`, `load=1` and dies with
  **exit 139** (SIGSEGV). The fault is the measurement, so there is nothing to compare past it.
- **Crate:** returns without walking. The walk is not "a no-op with the same answer": it
  constructs every algorithm of every activated provider into the store as a side effect, so the
  refusal is a real behavioural narrowing and is recorded as one rather than presented as
  equivalence.
- **Reason:** `D-NAMEMAP-DOALL-1`'s, exactly. The visitor is a function pointer the caller
  supplies; a NULL one is the caller's error, and an error is not a reason to take the caller's
  process down.
- **Claim removed:** `EVP_MD_do_all_provided` with a NULL visitor is not claimed compatible. It is
  claimed *safe*. With a visitor the entry point is compared normally.
- **Note:** this is the same class as `D-NAMEMAP-DOALL-1` recorded from the other side — a
  `do_all` whose visitor is forwarded rather than tested — and it is a separate entry because the
  two are reached through different exported entry points and a future reader of either should not
  have to find the other first.

### D-MAC-DUPCTX-NULL-1 — `EVP_MAC_CTX_dup` calls through a NULL `dupctx`

- **Obligation:** `EVP_MAC_CTX_dup` on a method that publishes no `OSSL_FUNC_MAC_DUPCTX`.
- **Authority:** **measured**. `crypto/evp/mac_lib.c` reaches
  `dst->algctx = src->meth->dupctx(src->algctx)` with no test on the pointer, and `dupctx` is
  deliberately **not** counted by `evp_mac_from_algorithm`'s structural check — so a method without
  a duplicator is perfectly fetchable and perfectly usable until it is duplicated. A program that
  registers a builtin provider publishing a MAC without `dupctx`, loads it, fetches it, makes a
  context and duplicates it prints `add_builtin=1`, `load=1`, `fetch=1`, `ctx_new=1` and dies with
  **exit 139** (SIGSEGV). The fault is the measurement, so there is nothing to compare past it.
  `RT-EVP-MAC` prints `NOT_MEASURED_AUTHORITY_FAULTS` at the boundary.
- **Crate:** answers **NULL**, which is not an invented answer: it is what the authority's own next
  statement does when a duplicator answers NULL (`if (dst->algctx == NULL) { EVP_MAC_CTX_free(dst);
  return NULL; }`). So the divergence is exactly one step wide — a missing duplicator is treated as
  a duplicator that could not duplicate — and the reference the duplicate took on the method is
  given back through `EVP_MAC_CTX_free` on the way out.
- **Reason:** an indirect call through a null pointer is not a contract to reproduce. This one is
  worth its own entry rather than being folded into D-MD-NULL-CALLBACK-1 because the *shape* is
  different in a way that matters to a reader: the digest class's faults are on a method a caller
  had to build by hand, whereas this one is on a method the library itself fetched from a provider
  whose dispatch table simply omitted an optional callback.
- **Claim removed:** `EVP_MAC_CTX_dup` on a method with no `dupctx` is not claimed compatible. It is
  claimed *safe*. On a method that publishes one — `RT-EVP-MAC`'s `court-mac5` — the call is
  compared normally, including the reference count it leaves behind.

### D-KEYMGMT-PARAMS-NULL-1 — the four `EVP_KEYMGMT` descriptor accessors dereference a NULL method

- **Obligation:** `EVP_KEYMGMT_gettable_params(NULL)`, `EVP_KEYMGMT_settable_params(NULL)`,
  `EVP_KEYMGMT_gen_settable_params(NULL)`, `EVP_KEYMGMT_gen_gettable_params(NULL)`.
- **Authority:** **measured**. Each is
  `void *provctx = ossl_provider_ctx(EVP_KEYMGMT_get0_provider(keymgmt)); if (keymgmt->X != NULL)
  return keymgmt->X(provctx); return NULL;` — the method pointer is dereferenced on the *first*
  line, before the callback is tested, so a NULL method is a SIGSEGV (exit 139) and not a NULL
  answer. Measured once with a standalone probe; `RT-EVP-KEYMGMT` prints
  `params.*.null_method=NOT_MEASURED_AUTHORITY_FAULTS` at all four sites rather than comparing a
  fault.
- **Crate:** answers **NULL**, which is the same answer each of the four gives for a live method
  whose callback is absent. The divergence is therefore exactly one input wide — a method that does
  not exist — and it is invisible to every caller that has a method, which is every caller the
  library's own code has.
- **Reason:** `D-NAMEMAP-DOALL-1`'s and `D-MD-NULL-CALLBACK-1`'s. The method pointer is the
  caller's input, and a caller that passes NULL has made a mistake; an input mistake is not a
  reason to take the caller's process down. It is recorded separately from
  the four accessors' sibling `evp_keymgmt_has`, which carries the same guard and cites the same
  class in its own doc, because the two are reached through different entry points.
- **Claim removed:** the four accessors with a NULL method are not claimed compatible. They are
  claimed *safe*. On a live method all four are compared normally, including which of the two
  provider tables came back.

### D-PKEY-AMETH-1 — `pkey_set_type`'s legacy-method lookup is Phase 8's, so a provider key's `type` stays `EVP_PKEY_KEYMGMT`

> **Superseded by D-PKEY-AMETH-3** for the eleven `standard_methods[]` rows the 8.8 landing
> (D353) now carries: `pkey_set_type` finds them, so a provider method named `"RSA"`, `"EC"`,
> `"DSA"`, `"DH"`, `"RSA-PSS"`, `"DHX"` or `"SM2"` takes the legacy NID into `pkey->type` exactly
> as the authority does. It is kept rather than deleted because the four `crypto/ec/ecx_meth.c`
> names it still describes are the whole of D-PKEY-AMETH-3's subject. The paragraphs below are the
> state before the 8.8 landing.

- **Obligation:** `EVP_PKEY_set_type_by_keymgmt` on a provider method whose **name is a legacy key
  type** -- `"RSA"`, `"EC"`, `"DSA"`, and the rest of the twelve -- and, through it,
  `EVP_PKEY_get_id`, `EVP_PKEY_get_base_id` and every accessor that branches on the resulting type.
- **Authority:** **read from the source, and the read is the whole finding.** `pkey_set_type` looks
  the type up with `EVP_PKEY_asn1_find_str(eptr, str, len)`, and when it finds a method it takes the
  **legacy** NID into `pkey->type` even though the key is provider-side: `if (ameth != NULL) { if
  (type == EVP_PKEY_NONE) pkey->type = ameth->pkey_id; } else { pkey->type = EVP_PKEY_KEYMGMT; }`.
  So `EVP_PKEY_get_id` on a provider key named `"RSA"` answers `EVP_PKEY_RSA`, and only a key whose
  name matches **no** legacy method answers the pseudo-NID `EVP_PKEY_KEYMGMT` (`-1`). The comment
  above the lookup explains why the field keeps its legacy meaning: "for any key type that has a
  legacy implementation, regardless of if the internal key is a legacy or a provider side one".
- **Crate:** answers `EVP_PKEY_KEYMGMT` in both cases, because `EVP_PKEY_asn1_find_str` and
  `EVP_PKEY_asn1_find` are `crypto/asn1/ameth_lib.c`'s and search `standard_methods[]` -- a
  compile-time table of the twelve `ossl_<alg>_asn1_meth` objects that Phase 8's units define
  (`docs/DECISIONS.md` D163, D165). The lookup is the only thing missing: the **name walk** that feeds
  it is written, including the two-name ambiguity refusal that makes `found[1] != NULL` an error.
- **Reason:** the dependency is a stratum boundary and not a choice, and it is the same boundary D163
  recorded for `evp_pkey_name2type`'s fallback and D165 for row 7.4l. Recording it as a divergence
  rather than as a deferral is what the gate's own rule forces: a deferral row is refused for a name
  the crate *defines* (`stale_deferral`), and `EVP_PKEY_set_type_by_keymgmt` is defined here.
- **Claim removed:** `EVP_PKEY_get_id` -- and therefore `EVP_PKEY_get_base_id`, `EVP_PKEY_can_sign`,
  `EVP_PKEY_get0_type_name`'s legacy arm and every `EVP_PKEY_is_a` comparison against a legacy
  spelling -- is not claimed compatible for a provider key whose name is among the twelve standard
  names. It is claimed compatible for a key whose name is not, which is the only case in which the
  authority and the crate agree today.
- **Trigger:** Phase 8's first commit that lands an `EVP_PKEY_ASN1_METHOD` object. At that point
  `find_ameth`'s body is the loop the authority writes and `pkey_set_type`'s `if (ameth != NULL)` arm
  becomes reachable; `RT-EVP-PKEY` is where the difference would be measured, and the measurement is
  `EVP_PKEY_get_id` on a fetched keymgmt named `"RSA"`.

### ~~D-PKEYCTX-LEGACY-ALG-1~~ — **WITHDRAWN: the released authority refuses this too**

**This entry is retained, struck through, because it was cited before it was written and writing
it would have recorded a divergence that does not exist. There is no behavioural difference
between the authority and the candidate at this site.**

- **What was claimed:** that `int_ctx_new` compares the caller's `id` against the fetched
  method's `legacy_alg` by way of `ossl_assert(id == tmp_id)`, that this assertion is "the
  identity function" under `NDEBUG` and therefore does not fire in the released authority, and
  that the crate -- which *does* raise and refuse -- was therefore deliberately diverging.
- **What the authority actually is:** under `NDEBUG`, `include/internal/common.h` defines
  `ossl_assert(x)` as `ossl_likely((x) != 0)`, which is the identity on a boolean, so
  `if (!ossl_assert(C))` is `if (!C)` -- a live guard. The released authority raises
  `ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR)`, frees the previously taken `EVP_KEYMGMT`
  reference, and returns NULL.
- **Measured:** the authority binary's `int_ctx_new` branches on `cmp %r12d,%eax; jne 22c07d`,
  and `22c07d` is `ERR_new` / `ERR_set_debug` with line `0x11c` (**284**, the `ERR_raise` line in
  `crypto/evp/pmeth_lib.c`) / `ERR_set_error(0x6, 0xc0103, 0)` -- `ERR_LIB_EVP` and
  `ERR_R_INTERNAL_ERROR` -- / `EVP_KEYMGMT_free` / a jump to the NULL-return epilogue. The crate
  writes `raise_site(&err_sites::PMETH_LIB_284)`, `EVP_KEYMGMT_free`, `return NULL`. The two are
  the same call, the same library, the same reason and the same cleanup.
- **How the error was produced:** the claim was written from the macro's *text* rather than from
  its expansion. `(x) != 0` is the identity function, and the comment stopped there -- but the
  guard is `!ossl_assert(C)`, and the identity function applied to `C` and then negated is `!C`,
  which fires. The one thing `NDEBUG` removes is the abort, not the refusal. Five other sites in
  the crate carried the same premise and the same conclusion; all six are corrected in
  `docs/DECISIONS.md` D167.
- **Candidate:** unchanged, and correct. It refuses exactly where the authority refuses.
- **Claim removed:** the claim of divergence, which was never made in the register -- only cited
  from `src/evp/pkey_ctx.rs`. That citation is gone; the site now states the authority's
  behaviour, and cites D167 for the measurement.

### D-PKEY-AMETH-2 — the two `find` functions answer NULL for the twelve legacy types, because `standard_methods[]` is Phase 8's

> **Superseded by D-PKEY-AMETH-3** for the eleven rows D353 published: `EVP_PKEY_asn1_find` and
> `EVP_PKEY_asn1_find_str` now answer the authority's own objects for those. It is kept rather than
> deleted because the four `crypto/ec/ecx_meth.c` types remain NULL, and because the engine-arm
> paragraph below is still the reason that arm is absent. The paragraphs below are the state before
> the 8.8 landing.

- **Obligation:** `EVP_PKEY_asn1_find` and `EVP_PKEY_asn1_find_str` on any of the twelve legacy key types
  (`EVP_PKEY_RSA`, `EVP_PKEY_EC`, `EVP_PKEY_DSA`, and the rest), and therefore every caller that
  resolves a type to its `EVP_PKEY_ASN1_METHOD` through them.
- **Authority:** `pkey_asn1_find` asks `app_methods` with `sk_EVP_PKEY_ASN1_METHOD_find` and then
  `standard_methods[]` with `OBJ_bsearch_ameth`; `standard_methods[]` is
  `crypto/asn1/ameth_lib.c`'s own table of the twelve `ossl_<alg>_asn1_meth` objects, sorted by
  `pkey_id`. So `EVP_PKEY_asn1_find(NULL, EVP_PKEY_RSA)` answers `&ossl_rsa_asn1_meth` and
  `EVP_PKEY_asn1_find_str(NULL, "RSA", 3)` answers the same object.
- **Crate:** answers NULL in both cases, and answers correctly for every method an application
  registered through `EVP_PKEY_asn1_add0`/`_add_alias`. `STANDARD_METHODS` is declared as a
  zero-length table with its reason at the site, and the twelve objects are Phase 8's (D163, D165).
  Both functions are **defined rather than withheld**: a consumer that calls them must link, and the
  answer is right in every state this crate can reach.
- **Reason:** the dependency is a stratum boundary and not a choice. It is the same boundary
  `D-PKEY-AMETH-1` records from the key-type side, reached through the public door instead of through
  `pkey_set_type`, and it is why that entry's crate description names these two functions.
  Distinguishing this from a *deferral* is what the gate's rule forces: a deferral row is refused for
  a name the crate defines (`stale_deferral`), and both names are defined here.
- **Engine arm, which is absent and is *not* a divergence:** `OPENSSL_NO_ENGINE` is undefined in the
  pinned profile, so the authority's `ENGINE_get_pkey_asn1_meth_engine` /
  `ENGINE_pkey_asn1_find_str` / `ENGINE_init` / `ENGINE_free` calls are compiled **in**. `ENGINE` is
  Phase 13's, so this crate has no engine type, no registry and no way to register one: a consumer
  that calls `ENGINE_add` fails to link before it can reach the state. With no engine registered the
  authority's own arm answers NULL and falls through to `*pe = NULL`, which is what the crate writes.
  The two answers are identical, so there is nothing to record as a divergence — only the reason the
  call is missing, which is stated at both sites.
- **Claim removed:** the claim that these two functions could not land at all. The module's own doc
  and the D-PKEY-AMETH-1 entry both described the empty table as the reason to *hold* them; the
  project's rule is the opposite — define the symbol, answer correctly for every reachable state, and
  record the divergence — and that is what `EVP_PKEY_asn1_get_count` and `_get0` already did for the
  same table.

### D-PKEY-AMETH-3 — the four `crypto/ec/ecx_meth.c` rows are withheld, so the two `find` functions answer NULL and `EVP_PKEY_type` answers `NID_undef` for X25519, X448, Ed25519 and Ed448

- **Obligation:** `EVP_PKEY_asn1_find(NULL, type)`, `EVP_PKEY_asn1_find_str(NULL, name, len)`,
  `EVP_PKEY_type(type)`, `EVP_PKEY_asn1_get0(idx)` and `EVP_PKEY_asn1_get_count()` for the four
  `crypto/ec/ecx_meth.c` key types -- `EVP_PKEY_X25519` (1034), `EVP_PKEY_X448` (1035),
  `EVP_PKEY_ED25519` (1087) and `EVP_PKEY_ED448` (1088) -- and, through `pkey_set_type`,
  `EVP_PKEY_set_type_by_keymgmt` on a provider method named `"X25519"`, `"X448"`, `"ED25519"` or
  `"ED448"`.
- **Authority:** `crypto/asn1/standard_methods.h` carries **fifteen** rows under the admitted
  `configuration.h` (D340 read the file for that fact; `OPENSSL_NO_ECX` is **absent**, so the four
  `#ifndef OPENSSL_NO_ECX` rows compile in). So `EVP_PKEY_asn1_find(NULL, NID_X25519)` answers
  `&ossl_ecx25519_asn1_meth`, `EVP_PKEY_asn1_find_str(NULL, "X25519", -1)` answers the same object
  (`ecx_meth.c:552-553` gives it that `pem_str`), `EVP_PKEY_type(NID_X25519)` answers `NID_X25519`,
  `EVP_PKEY_asn1_get_count()` answers **15** plus the application count, and `EVP_PKEY_asn1_get0(10)`
  answers `&ossl_ecx25519_asn1_meth` where the crate's index 10 is `ossl_sm2_asn1_meth`.
- **Crate:** `src/evp/pkey_asn1.rs`'s `STANDARD_METHODS` carries **eleven** rows -- the authority's
  fifteen minus the four above -- and every one of the eleven is the authority's object by address.
  The four absences are the table's only observable: the two `find` functions answer NULL for them,
  `EVP_PKEY_type` answers `NID_undef`, `EVP_PKEY_asn1_get_count()` answers 11 plus the application
  count, and a provider keymgmt named one of the four takes `EVP_PKEY_KEYMGMT` (`-1`) into
  `pkey->type` where the authority takes the legacy NID. The callers that see it are
  `EVP_PKEY_type`, `EVP_PKEY_assign`/`_set_type`/`_set_type_str`, `EVP_PKEY_get_id` and every
  `EVP_PKEY_is_a` comparison against an ECX spelling, plus the with provider `X25519`/`ED25519`
  method fetches that reach `EVP_PKEY_set_type_by_keymgmt`.
- **Reason:** `crypto/ec/ecx_meth.c` is 1,468 lines and fifty-five functions, and its callbacks
  reach `crypto/ec/ecx_key.c`, `crypto/ec/ecx_backend.c`, `crypto/ec/curve25519.c` (about 5,900
  lines) and all of `crypto/ec/curve448/` (about 3,400) -- roughly **9,000 authority lines** with no
  crate module and no stratum's obligation row (D316 names only the provider half of `ecx_key.c`).
  A `const EVP_PKEY_ASN1_METHOD` names its callbacks **by address**, so a row cannot exist until
  every callback it names does, and writing a row whose callback field is not the authority's would
  be a fabricated method rather than a smaller landing -- D341's rule, which this entry applies
  instead of violating. Landing the four rows is therefore a second unit of work the size of the one
  D353 records, not a step inside it.
- **Claim removed:** `EVP_PKEY_asn1_find`/`_find_str`/`EVP_PKEY_type`/`EVP_PKEY_asn1_get0`/
  `EVP_PKEY_asn1_get_count` parity for the four ECX types, and `pkey_set_type`'s legacy-NID answer
  for a provider method named one of their four PEM names. **Nothing else**: the other eleven rows,
  both `find` functions' alias walk and length rules, the engine-arm absence and every
  `EVP_PKEY_asn1_get0_info` field of the eleven are claimed and courted (`RT-AMETH`, 232
  observations, zero residuals).
- **This is not a `forensics/prerequisites.json` divergence record, and the gate is why.** The
  names a record would have to cover -- `ossl_ecx25519_asn1_meth` and its three siblings -- are
  `const` objects, not functions, so they are not in the internal-symbol universe the gate
  observes; a record naming them would fail the gate's direction D ("a divergence record may not
  cover a name the gate did not observe"). The four types are observed instead through the
  **`EVP_PKEY_asn1_find`/`_find_str`/`EVP_PKEY_type` answers**, which is where the consequence is
  visible to a caller, and `RT-AMETH` confines its arms to the eleven ids both sides carry for
  exactly that reason.
- **Trigger:** the slice that lands `crypto/ec/ecx_meth.c` and the ~9,000 lines its callbacks
  name -- at which point the four rows are appended to `STANDARD_METHODS` in `pkey_id` order (1034,
  1035, 1087, 1088, between `ossl_dhx_asn1_meth` at 920 and `ossl_sm2_asn1_meth` at 1172),
  `EVP_PKEY_asn1_get_count()` moves to 15, and this entry is removed with the table it describes.
- **The same four units are the `EVP_PKEY_METHOD` table's rows too (D355).** `crypto/evp/pmeth_lib.c`'s
  second `standard_methods[]` is an array of `pmeth_fn` **accessors** rather than of objects, and four
  of its ten rows are `ossl_ecx25519_pkey_method` (1034), `ossl_ecx448_pkey_method` (1035),
  `ossl_ed25519_pkey_method` (1087) and `ossl_ed448_pkey_method` (1088) -- all four defined in the
  same withheld `crypto/ec/ecx_meth.c`. The crate's `src/evp/pkey_ctx.rs`'s `PMETH_STANDARD_METHODS`
  therefore carries **six** rows where the authority carries ten, and the observable is
  `EVP_PKEY_meth_find(EVP_PKEY_X25519)` -- and its X448, Ed25519 and Ed448 siblings -- answering
  **NULL**, `EVP_PKEY_meth_get0(6..10)` answering NULL where the authority answers those four
  methods, and `EVP_PKEY_meth_get_count()` answering **6** where the authority answers 10. The
  callers that see it are `EVP_PKEY_CTX_new_id`'s legacy-method lookup and any enumeration by index,
  both of which fall through to the provider `EVP_KEYMGMT_fetch` the authority would have preferred
  the legacy method over. The six shared rows, `EVP_PKEY_meth_get0_info`'s two fields and
  `EVP_PKEY_meth_find`'s application-table-first rule are claimed and courted (`RT-AMETH`'s arm 8),
  and the trigger is the one above, one table over: the four accessors are appended to
  `PMETH_STANDARD_METHODS` in `pkey_id` order after `ossl_dhx_pkey_method` at 920.

### D-PBE-PKCS12-KEYGEN-1 — the six `PKCS12_PBE_keyivgen` rows of `builtin_pbe[]` carry no keygen

- **Obligation:** `EVP_PBE_find` and `EVP_PBE_find_ex` for the six NIDs `NID_pbe_WithSHA1And128BitRC4`
  (144), `NID_pbe_WithSHA1And40BitRC4` (145), `NID_pbe_WithSHA1And3_Key_TripleDES_CBC` (146),
  `NID_pbe_WithSHA1And2_Key_TripleDES_CBC` (147), `NID_pbe_WithSHA1And128BitRC2_CBC` (148) and
  `NID_pbe_WithSHA1And40BitRC2_CBC` (149) under `EVP_PBE_TYPE_OUTER`, and `EVP_PBE_CipherInit_ex`
  on an `ASN1_OBJECT` whose `OBJ_obj2nid` is one of the six.
- **Authority:** the six rows of `crypto/evp/evp_pbe.c:46-57` name `PKCS12_PBE_keyivgen` in the
  `keygen` column and `&PKCS12_PBE_keyivgen_ex` in the `keygen_ex` column, so `EVP_PBE_find_ex`
  answers **1** for each with both `cipher_nid` and `md_nid` set (`NID_rc4`/`NID_sha1`,
  `NID_rc4_40`/`NID_sha1`, `NID_des_ede3_cbc`/`NID_sha1`, `NID_des_ede_cbc`/`NID_sha1`,
  `NID_rc2_cbc`/`NID_sha1`, `NID_rc2_40_cbc`/`NID_sha1`) and both pointers **non-NULL**, and
  `EVP_PBE_CipherInit_ex` reaches `PKCS12_PBE_keyivgen_ex` (`crypto/pkcs12/p12_crpt.c:23`).
- **Crate:** the six rows are **present and in place**, so the return code and both NIDs are the
  authority's for all six; the two keygen columns are `None`, so `EVP_PBE_find`/`_ex` answers 1 with
  `*pkeygen == NULL` and `*pkeygen_ex == NULL`, and `EVP_PBE_CipherInit_ex` answers **0** without
  calling through either. Measured by `RT-EVP-PBE`: its `pbe.find.04`…`pbe.find.09` arms print
  `1,0,144,5,64`…`1,0,149,98,64` — the return code, the type, the NID and both NIDs — on both
  sides, and `pbe.find_plain.04`…`pbe.find_plain.09` print `1,5,64`…`1,98,64`, followed in each
  case by a fixed marker in place of the two presence answers, because the two libraries' answers
  there differ (non-NULL on the authority, `NULL` here) and printing them would report a registered
  difference as a residual.
- **Reason:** `PKCS12_PBE_keyivgen` and `PKCS12_PBE_keyivgen_ex` are declared in `pkcs12.h` and
  `forensics/atlas/symbol-ownership.json` gives both `owner_phase: 10`. A Rust `static` is fully
  initialised or it does not exist, so a row whose keygen column is another stratum's function
  cannot be written at all, and a placeholder would change `EVP_PBE_find`'s answer — which is the
  thing the table exists to give. The alternative the project's per-symbol rule would normally reach
  for, deferring the *readers* (`EVP_PBE_find`, `_ex`, `EVP_PBE_CipherInit*`), was measured and
  does not build: `PKCS5_v2_PBE_keyivgen_ex` calls `EVP_PBE_find_ex` at `p5_crpt2.c:133` and
  `PKCS5_v2_PBKDF2_keyivgen_ex` calls `EVP_PBE_find` at `:230`, so deferring the readers would take
  four of this slice's own mandated exports with them and leave the court unable to observe the
  table at all. `docs/DECISIONS.md` D192 carries the argument and the cost.
- **Claim removed:** `EVP_PBE_find`/`_ex`'s two keygen out-parameters, and
  `EVP_PBE_CipherInit_ex`'s behaviour as a whole, are not claimed compatible for these six NIDs.
  The return code and both NID out-parameters **are** claimed compatible, for all thirty-four rows.
  The same record covers the guard in `EVP_PBE_CipherInit_ex` and in `PKCS5_v2_PBE_keyivgen_ex` that
  answers 0 where the authority would call a NULL pointer: the authority's eighteen `PRF` rows carry
  no keygen in either column, so `EVP_PBE_CipherInit_ex` on one of those objects — and on a KDF row
  a caller added with `EVP_PBE_alg_add_type`, which leaves `keygen_ex` empty — faults there.
- **Trigger:** Phase 10's first commit that lands `crypto/pkcs12/p12_crpt.c`. At that point the six
  rows take the two function addresses and this entry is removed with them; `RT-EVP-PBE`'s
  `pbe.find.04`…`pbe.find.09` arms would gain the two presence answers, which is the measurement.

### D-EVP-CIPHER-LEGACY-NID-1 — a fetched provider cipher's legacy NID is `NID_undef`, because the legacy table is Phase 13's

- **Obligation:** `EVP_CIPHER_get_nid` on a method returned by `EVP_CIPHER_fetch` whose name is a
  legacy name, and every caller that reads the result — measured here through `EVP_PBE_alg_add`,
  whose cipher argument is converted with `EVP_CIPHER_get_nid` (`crypto/evp/evp_pbe.c:238`).
- **Authority:** `evp_cipher_from_algorithm` calls `set_legacy_nid` over the method's names, which
  looks each one up in the `OBJ_NAME` table under `OBJ_NAME_TYPE_CIPHER_METH`. That table is
  populated by the legacy wrappers (`EVP_des_cbc` and its hundred and sixty siblings), so a fetch of
  `"DES-CBC"` answers `nid == NID_des_cbc` (**31**) and `EVP_PBE_alg_add` stores `31`.
- **Crate:** answers `NID_undef` (**0**), because those wrappers are Phase 13's and the table is
  empty. Measured by `RT-EVP-PBE`: the `EVP_PBE_alg_add` arm's stored `pcnid` is 31 on the authority
  and 0 here, while the *digest* half of the same arm agrees — `EVP_MD_get_type` answers 0 on both
  sides, which is the observation `docs/DECISIONS.md` D148 already recorded from `RT-FETCH`.
- **Reason:** the dependency is a contents boundary and not a choice: `set_legacy_nid`'s *code* is
  7.3b's and landed, and what it finds is Phase 13's. Recording it as a divergence rather than a
  deferral is what the gate's rule forces, as in D-PKEY-AMETH-1 and D-PKEY-AMETH-2.
- **Claim removed:** the legacy NID of a fetched provider method is not claimed compatible. Every
  other observable of the fetch — the name, the description, the parameters, the two length
  constants and the provider — is, and the *fetch* itself is unchanged: this is a value the method
  carries, not a refusal.
- **Trigger:** Phase 13's first legacy cipher wrapper. `RT-EVP-PBE`'s
  `pbe.cipher_nid.legacy` marker is where the difference would be measured, and
  `pbe.alg_add.methods_nids` is the arm it holds back.

### D-CBCHMAC-MULTIBLOCK-ENC-1 — the multiblock *encrypt* parameter is refused, because its IVs come from the random layer

- **Obligation:** `EVP_CIPHER_CTX_set_params` with `OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC` (and its
  `..._ENC_IN` companion) on a fetched `AES-{128,256}-CBC-HMAC-SHA{1,256}` context, and the bytes it
  writes to the caller's `out` buffer.
- **Authority:** `aes_set_ctx_params` (`cipher_aes_cbc_hmac_sha.c:150-170`) hands the parameter to
  `tls1_multiblock_encrypt`, whose body is `tls1_multi_block_encrypt`
  (`cipher_aes_cbc_hmac_sha1_hw.c:121`) and whose first act is
  `RAND_bytes_ex(ctx->base.libctx, blocks[0].c, 16 * x4, 0)` (`:146`). Those `x4` sixteen-byte
  values become each interleaved record's explicit IV, so the written ciphertext is a function of
  them: with the call answered, the parameter returns 1 and `tls1multi_enclen` becomes the packed
  length.
- **Crate:** answers **0** with no error queued, which is the value the authority itself answers when
  that `RAND_bytes_ex` call fails. `crypto/rand/` is Phase 9's; there is no DRBG, so there is no
  value to substitute.
- **Reason:** the dependency is a missing subsystem rather than a choice. `tls1_multiblock_aad` and
  `tls1_multiblock_max_bufsize` — the other two thirds of the same contract — need no randomness and
  **are** transcribed and courted by `RT-CIPHER`'s `cbchmac.*.mbaad*` and `cbchmac.*.g.maxbufsz`
  arms, so the row's stitched surface is narrowed rather than absent. This is the same boundary
  D234 records for the `AES-*-GCM` rows and D237 for `DES3-WRAP`.
- **Claim removed:** the `tls1multi_enc` parameter and `tls1multi_enclen` after it are not claimed
  compatible for these four rows. Every other observable of the rows is: the fetch, the flags, both
  key/IV/block lengths, all eight settable keys, all nine gettable keys, the multiblock AAD
  parameter, and the whole TLS 1.0 record including its refusal arm.
- **Trigger:** Phase 9's first commit that lands `crypto/rand/`. At that point
  `tls1_multiblock_encrypt` is written from `tls1_multi_block_encrypt` and
  `RT-CIPHER` gains the `cbchmac.*.mbenc` arm; the entry is removed with the arm's green.

### D-CBCHMAC-MAXBUFSZ-ASSERT-1 — `tls1multi_maxbufsz` before `maxsndfrag` aborts the authority and is answered here

- **Obligation:** `EVP_CIPHER_CTX_get_params` for `OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE`
  on a context whose `multiblock_max_send_fragment` is still zero, which is every context that has
  not set `OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT`.
- **Authority:** `aesni_cbc_hmac_sha1_tls1_multiblock_max_bufsize`
  (`cipher_aes_cbc_hmac_sha1_hw.c:697-704`) begins with
  `OPENSSL_assert(ctx->multiblock_max_send_fragment != 0)`. The assertion is **live in the pinned
  build** — measured, not assumed: the arm that read the buffer size first aborted the authority with
  `cipher_aes_cbc_hmac_sha1_hw.c:701: OpenSSL internal error: assertion failed:
  ctx->multiblock_max_send_fragment != 0`, exit status 134, which is why `RT-CIPHER` sets the
  fragment before it reads the size.
- **Crate:** computes the arithmetic anyway and answers **53** — `5 + 16 + ((0 + 20 + 16) & -16)` —
  where the authority terminates the process.
- **Reason:** reproducing an abort is not a compatibility property a library can hold: the crate
  forbids `panic` in production code for the same reason, and a deliberate `abort()` on a query
  would turn a caller's diagnostic into a denial of service. The divergence is in the safe
  direction, and it is recorded rather than left implicit because a *difference* on this path is
  otherwise invisible: a caller who never sets the fragment sees a number here and a dead process
  there.
- **Claim removed:** the abort itself is not claimed compatible. The value the function computes for
  a **non-zero** fragment is, and `RT-CIPHER`'s `cbchmac.*.g.maxbufsz` arm observes it with the
  fragment set to 16384, where both sides answer 16437.
- **Trigger:** none planned: this is a permanent, deliberate safety divergence. If a caller needs
  parity with the abort, that is `docs/DECISIONS.md` D276's to revisit, not an arm's.

### D-EC-1 — `curve_list[]`'s method column is not transcribed, because its one non-NULL value is a perlasm-only method whose table names units 8.7 does not own

> **Superseded by D-EC-2**, which records the same column with the answer the 8.7 landing actually
gives. It is kept rather than deleted because its *reason* -- the perlasm-only method -- is the
reason D-EC-2 gives too, and because D336, D338 and D339 cite it by number. The paragraph below is
D334's state, when the column was recorded as a NULL rather than resolved.

- **Obligation:** `EC_GROUP_new_by_curve_name(nid)`'s answer for `NID_X9_62_prime256v1`, and the
  method identity `EC_GROUP_method_of` reports for it.
- **Authority:** `crypto/ec/ec_curve.c:2678-2688` gives that row `EC_GFp_nistz256_method`, because
  `ECP_NISTZ256_ASM` is defined on this profile; the other eighty-one rows' fourth column resolves
  to `0`. The one non-NULL symbol is `ec_local.h`'s internal and **not** a DSO export — measured,
  not read: `nm -D` on the admitted prefix lists `EC_GF2m_simple_method`, `EC_GFp_mont_method`,
  `EC_GFp_nist_method` and `EC_GFp_simple_method` and no `EC_GFp_nistz256_method`.
- **Crate:** the built-in curve table, `curve_list[]`'s rows, `EC_get_builtin_curves`,
  `EC_curve_nid2nist`, `EC_curve_nist2nid` and `OSSL_EC_curve_nid2name` are transcribed and courted
  (`RT-EC`, 483 observations); the method column is recorded per row in
  `forensics/atlas/ec-curves.json` with the profile's `#if` resolution and the probe's own method
  observation beside it, and `src/ec/curve.rs`'s module documentation says why at the field it would
  occupy.
- **Reason:** a `None` in that column where the authority has a function would be a *fabricated
  value*, which is a stronger prohibition than an omission. The column's only two readers are
  `EC_GROUP_new_by_curve_name_ex` and its static `ec_group_new_from_data`, and
  `ec_group_new_from_data` **branches on** `curve.meth` — so writing the branch over a NULL would
  give `NID_X9_62_prime256v1` a different `EC_GROUP_method_of` than the authority the moment either
  constructor exists. Building the column needs `EC_GFp_nistz256_method`, whose `EC_METHOD` table
  (`ecp_nistz256.c:1569-1630`) names `ossl_ec_key_simple_*` (`ec_key.c`),
  `ossl_ecdh_simple_compute_key` (`ecdh_ossl.c`) and `ossl_ecdsa_simple_*` (`ecdsa_ossl.c`) — the
  key layer and the two units `docs/PHASE-8-SUBPHASES.md` puts after this block. Its field
  arithmetic is itself perlasm-only, so D274's rule applies to it: the crate supplies the
  construction and `RT-EC` becomes the court that proves it is *this* implementation's observable
  behaviour.
- **Claim removed:** the method column, and therefore `EC_GROUP_method_of` on a
  `NID_X9_62_prime256v1` group. **Nothing else**: every other column of every row, the whole
  eighty-two-row order, the two group constructors' *absence* (they are `open` in
  `forensics/phase8-obligations.json`, not divergent) and all three name lookups are claimed and
  courted.
- **Trigger:** the slice that lands `ec_key.c`, `ecdh_ossl.c` and `ecdsa_ossl.c` — at which point
  the column is written, the `EcListElement` field is added, and the divergence is removed with the
  arm that observes `EC_GROUP_method_of(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1))`. The
  unit test `the_table_is_the_authoritys_eighty_two_rows_in_order` and the generator's
  `method_column_has_one_non_null_row` check are the tripwires: both name this row, so the next
  person cannot add the field without reading this entry.
  That slice landed in D340 and **the trigger fired the other way**: the column is written, its one
  non-NULL row is resolved to `EC_GFp_simple_method`, and the divergence is *recorded* rather than
  removed, because the perlasm method still cannot be built. See **D-EC-2**.

### D-EC-2 — the `NID_X9_62_prime256v1` row resolves to `EC_GFp_simple_method` where the authority answers `EC_GFp_nistz256_method`, and that one row is the whole of the divergence

- **Obligation:** the method identity `EC_GROUP_method_of` reports for
  `EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)`, and therefore every point operation performed on
  that group's `EC_METHOD`.
- **Authority:** `EC_GFp_nistz256_method` — `crypto/ec/ec_curve.c:2678-2688` gives that row the
  method because `ECP_NISTZ256_ASM` is defined on this profile and `ec_nistp_64_gcc_128` is not, and
  the other eighty-one rows' fourth column resolves to `0`. Measured against the admitted prefix
  rather than read: a probe compiled against
  `forensics/authorities/prefix/openssl-3.6.4-production/` reports that group's
  `EC_GROUP_method_of` matching **none** of the four DSO exports `EC_GFp_simple_method`,
  `EC_GFp_mont_method`, `EC_GFp_nist_method` and `EC_GF2m_simple_method`, while the same `p`/`a`/`b`
  through `EC_GROUP_new_curve_GFp` answers `EC_GFp_mont_method`. The one non-NULL symbol is
  `ec_local.h`'s internal and is **not** a DSO export.
- **Crate:** `src/ec/curve.rs`'s `curve_list_method` resolves that row to `EC_GFp_simple_method`, and
  every other row to `None`, exactly as every NULL row resolves through `EC_GROUP_new_curve_GFp`
  (`src/ec/cvt.rs`, which is `EC_GFp_mont_method()` unconditionally on this profile, matching the
  authority). `ec_group_new_from_data` is transcribed whole and its `curve.meth` branch is real; the
  field it reads is the divergence, and `forensics/atlas/ec-curves.json` records the resolution per
  row — the generator's `method_column_resolves_for_every_row` check fails if a row's method is
  absent from the commit's four tables.
- **Reason:** `crypto/ec/ecp_nistz256.c`'s table (`:1569-1630`) is ordinary C, but every field
  operation it names — `ecp_nistz256_mul_mont`, `_sqr_mont`, `_point_add`, `_point_double`,
  `_gather_w5`/`_scatter_w5` and the rest — is `crypto/ec/ecp_nistz256-x86_64.s`, generated by
  perlasm from `asm/ecp_nistz256-x86_64.pl`, with **no `#else` arm** (D334 measured this). Inventing
  a construction would be the fabricated value D334 refused for the column itself, one level down;
  and D274's rule, which lets the crate supply a construction for a perlasm-only function and make a
  court prove it is *this* implementation's behaviour, does not reach this one either — a
  Montgomery-domain representation is observable through every subsequent multiplication, so a
  different construction is a different curve arithmetic rather than a different instruction
  schedule.
- **Observable consequences, which are what make this a divergence rather than an omission:**
  (a) `EC_GROUP_method_of` answers `EC_GFp_simple_method` where the authority answers
  `EC_GFp_nistz256_method`. That comparison is **not carried as an `RT-EC` arm**, and the integration
  plan's §5 step-6 sentence that says it is cannot be: a differential court's verdict is `pass` only
  when the residual set is empty (`forensics/tools/phase8_courts.py`), so an arm that *must* differ
  between the two sides is a known failure rather than a court arm, and `run_courts.py` requires
  `all_pass`. `RT-EC` observes the other eighty-one rows instead, comparing each group's identity
  against the four tables it calls in the probe; this divergence is measured on the authority side by
  the one-off probe above and on the crate side by the generator, which is the same shape every
  crash-boundary entry in §6 uses (a boundary is measured once and printed, and the observations
  around it are compared). (b) Every `NID_X9_62_prime256v1` operation runs the generic Weierstrass
  code path rather than the 4-limb Montgomery arithmetic, so a `secp256r1` signature is the same
  *value* on both sides — the group is the same — but not the same *code path*; `RT-EC`'s ECDSA
  sign-then-verify and ECDH agreement arms observe the values and agree. (c) `EC_nistz256_pre_comp_dup`
  and `_free` (`crypto/ec/ecp_nistz256.c`) are not given a module, so `EC_GROUP_copy` and
  `EC_pre_comp_free` do not transcribe their two `#ifdef ECP_NISTZ256_ASM` arms — an omission that
  is unreachable while no nistz256 group can be constructed, and is named at the arm rather than left
  as an untaken branch (`src/ec/lib.rs:92-96`, `:201-216`). (d) `EC_GROUP_have_precompute_mult`
  answers 0 for that group where the authority answers 1, which is why `RT-EC` skips the direct arm
  for that one NID and courts the pre-computation path only through `EC_POINT_mul`'s ladder arm, as
  the plan's §5 says.
- **Claim removed:** the method identity of the one curve, that group's pre-computation path, and the
  `have_precompute_mult` answer for it. **Nothing else**: all eighty-two rows in order, both group
  constructors, every field operation of the four landed `EC_METHOD`s and all three name lookups are
  claimed and courted (`RT-EC`, 2134 observations, zero residuals).
- **Trigger:** the slice that supplies a construction for the perlasm unit — at which point
  `curve_list_method` answers `EC_GFp_nistz256_method` for that NID, the `PCT_nistz256` arm of
  `EC_pre_comp_free`/`EC_GROUP_copy` is transcribed, and this entry is removed with the boundary it
  records.
- **Supersedes D-EC-1**, whose subject was the same column recorded as "not transcribed": D-EC-2 is
  the same refusal with the answer the landing actually gives, which is stronger than a NULL because
  it is a stated behaviour with a measurement behind it rather than a field left empty.

### D-DECODER-ABSENT-1 — the crate publishes no provider decoder, so every `OSSL_DECODER`-dependent reader answers the legacy leg's answer or fails

- **Obligation:** the readers whose authority body tries `OSSL_DECODER` first: `d2i_PUBKEY` and
  `d2i_PUBKEY_ex` (`crypto/x509/x_pubkey.c:541`, `:547`) through `x509_pubkey_ex_d2i_ex`'s
  opportunistic arm (`:210`), and `pem_read_bio_key_decoder` (`crypto/pem/pem_pkey.c:35`), which
  `PEM_read[_bio]_PrivateKey[_ex]` and `PEM_read[_bio]_PUBKEY[_ex]` all reach through
  `pem_read_bio_key` (`:216`).
- **Authority:** the default provider supplies the DER and PEM decoders, so each of these arms
  decodes. Measured for `d2i_PUBKEY` on a 1024-bit RSA `SubjectPublicKeyInfo`: the authority answers
  a key (`EVP_PKEY_get_id` 6, `EVP_PKEY_get_bits` 1024). Measured for `PEM_read_bio_Parameters` on a
  written `-----BEGIN DH PARAMETERS-----` block: the authority answers a key (`EVP_PKEY_get_id` 28,
  `EVP_PKEY_get0_DH` non-NULL), and the legacy parameters arm is **unreachable on this revision**
  because its guard is `(selection & EVP_PKEY_KEYPAIR) == 0` while `EVP_PKEY_KEYPAIR` contains every
  parameter bit.
- **Candidate:** the decoder context is built and carries **no instances**
  (`src/decoder_meth.rs`: every `OSSL_OP_DECODER` provider row is unimplemented here), so
  `OSSL_DECODER_from_data`/`_from_bio` take their zero-decoder arm, `d2i_PUBKEY` answers NULL for a
  decodable input, and `pem_read_bio_key_decoder` returns NULL after its first failed walk. The
  legacy fallback that follows is the authority's own code path, so
  `PEM_read[_bio]_PrivateKey[_ex]` and `PEM_read[_bio]_PUBKEY[_ex]` are **unaffected** on every input
  the legacy methods can read — a traditional `RSA PRIVATE KEY` block is decoded by the ameth leg on
  both sides, measured.
- **The one observable inside the shared path.** The decoder leg's failure leaves a different record
  on the queue: the authority raises `ERR_R_UNSUPPORTED` at `crypto/encode_decode/decoder_lib.c:104`
  ("No supported data to decode"), the candidate `OSSL_DECODER_R_DECODER_NOT_FOUND` at `:60`. Both
  answer NULL, so the *result* agrees and the loop's retry count is the only other difference.
  `courts/phase8/rt_pubkey_probe.c` therefore observes the queue's **count** for those arms and
  names this entry as the reason the record is not carried as a residual; every arm whose whole path
  is shared carries the full coordinate (`drain`). `d2i_PUBKEY`'s refusal is observed through a
  zero-length input, which fails in the ASN.1 layer at `crypto/asn1/tasn_dec.c:212` on both sides.
- **Reason:** the missing piece is the provider layer, not the readers. Transcribing a reader whose
  answer would differ is the class D349 refused; withholding the two `PEM_read_bio_Parameters*`
  spellings, whose only successful arm is the decoder, is the same refusal applied where no legacy
  fallback exists (`src/pem/pem_pkey.rs`).
- **Claim removed:** that `d2i_PUBKEY`/`d2i_PUBKEY_ex` decode a `SubjectPublicKeyInfo` the default
  provider's DER decoder reads, that `pem_read_bio_key_decoder` can succeed, and that
  `PEM_read_bio_Parameters`/`_ex` answer a key. **Nothing else**: the `X509_PUBKEY` object layer,
  `ossl_d2i_PUBKEY_legacy` and the type-specific `d2i`/`i2d` pairs for RSA, DSA and EC are the
  authority's own code on both sides and are courted in full (`RT-PUBKEY`, 100 observations, zero
  residuals).
- **Trigger:** the slice that supplies a provider decoder — the DER/PEM decoder rows and the
  keymgmt rows they construct into. At that point each of the three arms decodes, the queue record
  becomes the authority's, and this entry is removed with the boundary it records. **Recorded by
  D369.**
