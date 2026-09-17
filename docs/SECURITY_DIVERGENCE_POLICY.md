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
