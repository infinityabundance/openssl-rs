# ABI Policy

Status: **constitution** (Phase 0).

OpenSSL's same-major-version policy makes ABI compatibility a **contract**, not
an incidental implementation detail. A function existing is not parity; a symbol
linking is not parity.

## 1. Source vs binary compatibility are separate claims

They are proved independently, and the **cross combinations are mandatory**:

```
oracle headers   + oracle DSO
candidate headers + candidate DSO
oracle headers   + candidate DSO        <-- binary compatibility
candidate headers + oracle DSO          <-- reverse direction
```

The cross combinations are what distinguish source compatibility from binary
compatibility. ABI parity is **not** promoted merely because applications
recompiled against candidate headers work.

## 2. Layout probes

For every public layout-bearing object, the same C probe is compiled against both
header sets and compared **byte-identically**:

```
sizeof        alignof       offsetof (every public field)
enum constants              macro constants where materialised
calling-convention assumptions
```

Where a struct is opaque, the probe establishes opacity itself (a compile that
must fail, does fail).

## 3. Symbols and versions

Symbol **presence is not sufficient**. On platforms supporting symbol versions,
the appropriate OpenSSL symbol versions are preserved.

- Candidate export/version scripts are **generated** from the authority's symbol
  atlas, never hand-maintained.
- Courts use `readelf`, `nm`, `objdump`, dynamic-loader probes and
  `dlsym`/`dlvsym`.
- Versioned symbol resolution is tested explicitly: an application expecting
  `OPENSSL_3.x.y`-versioned symbols must not accidentally bind to unversioned
  substitutes.

The Phase 1 atlas already establishes the real version namespace for the
production authority:

```
OPENSSL_3.0.0  3.0.3  3.0.8  3.0.9  3.1.0  3.2.0  3.3.0  3.4.0  3.5.0  3.6.0
```

and that the generated `libcrypto.ld` version script and the built DSO's exports
agree exactly (5896 symbols), with zero hard residuals.

## 4. Distribution shell

Reconstructed before complex semantics are implemented:

```
include tree          generated version headers     compile-time constants
feature macros        pkg-config metadata           library names / SONAMEs
symbol version ns     linker scripts / export maps  installation paths
provider search paths configuration defaults        executable naming
```

A trivial external consumer must build and load correctly **first**; only then
does semantic work begin.

## 5. Contamination

- `libcrypto` and `libssl` keep separate symbol namespaces, SONAMEs and runtime
  dependency relationships. They are never collapsed.
- The court proves non-contamination: any produced artifact whose dynamic closure
  resolves to a non-authority `libcrypto`/`libssl` is a hard failure
  (`docs/AUTHORITY_POLICY.md` §4.1).
- The **downstream binary-substitution seal** is one of the strongest gates: build
  a consumer once against OpenSSL headers/libs, run it against OpenSSL, then
  substitute compatible `openssl-rs` DSOs **without recompilation** and run the
  identical executable.

## 6. Platform scope

A Linux receipt proves Linux behaviour. It proves nothing about Windows DLL ABI.
Use **platform-scoped seals**; Linux x86_64 is sealed first because it provides
the strongest ELF archaeology tooling. Never write "drop-in OpenSSL replacement"
without the supported platform/version/build-profile scope immediately available.

## 7. Deprecated surface counts

OpenSSL 3 retains substantial legacy API surface. Deprecated interfaces are
inventoried mechanically and belong to the ABI contract. Where a legacy API is
implemented internally through modern machinery, that is acceptable **only** when
the observable contract matches. See `docs/PARITY_MODEL.md` §1 —
`OPENSSL_API_COMPAT` and `OPENSSL_NO_DEPRECATED` are themselves observable.
