# Unsafe Rust Policy

Status: **constitution** (Phase 0). Referenced by `docs/CUSTODIAN_CONTRACT.md` §4.

## 1. When `unsafe` is permitted

Only where the contract requires it:

- C ABI boundaries;
- raw ownership compatibility (see `docs/OWNERSHIP_MODEL.md`);
- platform syscalls;
- dynamic loading (`dlopen`/`dlsym`/`dlvsym`, `LoadLibrary`);
- CPU intrinsics (see Phase 19);
- exact memory-layout requirements (public struct layout, `offsetof`-visible
  fields, version-script/ABI-visible objects).

## 2. Structure

- `unsafe` is concentrated in **narrow modules** (typically `src/ffi/**`,
  `src/platform/**`, and specific `mem`/`atomic` primitives), not sprinkled
  through algorithmic code.
- Each module carries a `// SAFETY:` invariant catalogue at the top describing
  every precondition its `unsafe` blocks assume.
- Every `unsafe` block states, in a comment, *which* catalogue invariant it
  relies on and *why* it holds at that point.

## 3. Panic containment

- No Rust panic may unwind across a C ABI boundary.
- Every exported `extern "C"` function has an unwind boundary
  (`catch_unwind`) or is otherwise guaranteed non-unwinding.
- Panics on the FFI path are a **hard failure**, detected by tests, not merely
  reviewed.

## 4. Testing of invariants

Unsafe invariants are aggressively tested:

- unit tests per invariant, including negative tests;
- `Miri` over the safe-testable subset;
- address/thread sanitizers and UB instrumentation;
- canary allocators for lifetime/aliasing invariants;
- fuzzing across the FFI boundary.

## 5. Authority undefined behaviour

The authority is written in C and may contain undefined behaviour. The candidate
does **not** reproduce UB merely because one observed authority run yielded a
particular result. Such observations become recorded *compatibility boundaries*
(`docs/RELEASE_GATES.md` §6), not behaviours to imitate.
