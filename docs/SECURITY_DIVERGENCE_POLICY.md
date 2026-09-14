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
