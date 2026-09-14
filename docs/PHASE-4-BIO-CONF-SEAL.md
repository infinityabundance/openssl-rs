# Phase 4 seal — BIO, CONF and the buffer object

**STATUS: IN PROGRESS. This phase is not complete and must not be read as if it
were.** No symbol in this stratum is `PARITY_VERIFIED`; the strongest claim any of
them carries is `IMPLEMENTED`, and only for the behaviours the `RT-BIO` probe
actually exercises.

- Authority: `openssl-3.6.4-production`
- Court result: `artifacts/phase4/COURTS.json` (`RT-BIO`, 212 observations, 0 residuals)
- Obligation ledger: `forensics/phase4-obligations.json` (123 implemented, 14 deferred, **119 open**)
- Derived state: `forensics/phase-state.json` (Phase 4 `in-progress`)

## What the court establishes

`courts/phase4/rt_bio_probe.c` is compiled twice — once against the admitted
authority and once against the candidate distribution shell — run, and the two
transcripts are diffed line by line. `RT-BIO` passes with **212 observations and
zero residuals**. The behaviours covered are:

| area | what is compared |
|---|---|
| method identity | name and `BIO_TYPE_*` word for the memory, secure-memory, null, null-filter and socket methods |
| lifecycle | `BIO_new`/`BIO_new_ex`, `init`/`shutdown` defaults, `BIO_up_ref`, both `BIO_free` calls, `BIO_vfree` |
| memory reads/writes | write, `write_ex` and its out-parameter, `pending`, `wpending`, byte counters, the `BIO_read` byte-count contract against the `BIO_read_ex` success-flag contract, the empty-buffer return value and retry flag, `eof_return` |
| memory controls | `gets` to the first newline, `seek`/`tell` inside and past the window, `reset`, `get_mem_ptr` and the observable `BUF_MEM` growth policy |
| read-only memory | `BIO_new_mem_buf`, EOF reads, the refused write and the exact raised reason |
| chains | `push`, `pop`, `next`, `find_type` with and without a type mask, forwarding through a filter |
| `dup_chain` | field copying, `BIO_CTRL_DUP`, `ex_data` duplication, independence from the original |
| callbacks | the modern callback's operation sequence and the deprecated get/set pair |
| flags and retry | set/clear/test, `should_read`, retry type and reason, `BIO_get_retry_BIO` |
| control failure classes | `NULL` BIO is `-1`, unsupported method is `-2` **with a raised reason**, unknown command is `0`, plus `pointer`/`int`/`callback` control wrappers |
| method API | the legacy/modern slot asymmetry: `BIO_meth_get_read` returns the legacy pointer while `BIO_meth_get_read_ex` returns the dispatch slot |
| printf and dump | `BIO_printf`, `BIO_snprintf` including the truncation return, `BIO_indent` and its clamp, `BIO_dump`, `BIO_dump_indent`, short dumps, `BIO_hex_string` |
| buffer object | `BUF_MEM_new`/`_new_ex`/`_grow`/`_grow_clean` including the exact `(len+3)/3*4` growth and the `max` the caller can observe |
| sockets | socket BIO creation, `BIO_C_GET_FD`, transfer, `BIO_socket_nbio`, the error classifiers and `BIO_socket_wait` on a ready descriptor |

## What the court found

The court is not decoration; it found four genuine implementation defects that
reading `bio.h` could not have exposed. Each is now reproduced from the measured
behaviour rather than from memory:

1. `BIO_snprintf` returns **-1 on truncation**, not the length that would have
   been written.
2. `BIO_sock_error` returns the **current socket error** on a failed
   `getsockopt` (measured: `9`, `EBADF`), not a generic `1`.
3. `BIO_ctrl(b, BIO_C_GET_FD, …)` returns the **descriptor**, and `-1` for an
   uninitialised BIO; `BIO_C_SET_NBIO` is absent from the socket control switch,
   so it reports `0`.
4. `sock_new` leaves `init == 0`. A bare `BIO_new(BIO_s_socket())` therefore
   reports `-1` from `BIO_C_GET_FD` and its destructor must **not** close
   descriptor 0. `BIO_new_socket` is `BIO_set_fd`, not two field writes; writing
   the fields directly leaves `init` at `0` and the BIO unusable.

Two further defects were in the probe, not the implementation, and were fixed on
the probe side: `BIO_set_data` on a memory BIO replaces the method's private
pointer (so the destructor freed a stack address), and `BIO_method_name` takes a
`BIO`, not a method table.

## What is not established

- **119 open obligations of this stratum**, enumerated in
  `forensics/phase4-obligations.json`. They are: the `BIO_ADDR`/`BIO_ADDRINFO`/
  `BIO_lookup` family and the connect/accept BIOs built on it; the datagram BIOs;
  the buffer, linebuffer, readbuffer, prefix, non-blocking-test and base64
  filters; `BIO_s_bio`; `CONF_`/`NCONF_`; the six `OPENSSL_LH_*stats*`; the three
  `ERR_print_errors*` plus `ERR_add_error_mem_bio`; and `OBJ_create_objects`.
- **14 hand-offs** to later strata, each with its owning phase and reason:
  ASN.1-prefix filters and `BIO_new_NDEF` (Phase 5), `BIO_s_core` and
  `BIO_new_from_core_bio` (Phase 6), the digest/cipher/reliable filters (Phase 7),
  `BIO_new_CMS` and `BIO_new_PKCS7` (Phase 12).
- **No CONF court.** `CONF`/`NCONF` are entirely unimplemented, so there is
  nothing to compare.
- **The `clippy --all-targets -- -D warnings` gate does not pass** for the new
  BIO modules: 201 diagnostics, all of the form "`unsafe` function's docs are
  missing a `# Safety` section" or "`unsafe` block missing a safety comment".
  `docs/UNSAFE.md` requires both, and this is recorded as open debt rather than
  suppressed with an `allow`.
- **No FRF court, receipt or claim** has been produced for this stratum yet, and
  no Gemel checkpoint.

## Non-claims

Nothing here says the candidate is a drop-in replacement for OpenSSL's BIO. A
passing transcript means the candidate behaved identically to the authority for
the 212 observations above, on one platform, for one build profile. It is not
evidence about anything the probe does not touch, and it is not cryptographic or
security evidence (`docs/PARITY_MODEL.md`, `docs/NON_CLAIMS.md`).
