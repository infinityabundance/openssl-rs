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

Every entry below was found by running a Phase 3 probe against the authority
(`courts/phase3/`) and observing a fault. A probe cannot compare a crash, so in
each case the probe prints a `NOT_MEASURED_AUTHORITY_FAULTS` marker: the boundary
is visible in the transcript rather than silently absent from it. The
observations that *can* be made around each boundary are compared normally.

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
