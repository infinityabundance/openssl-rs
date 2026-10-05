#!/usr/bin/env python3
"""openssl-rs — the Phase 18 provenance regression court.

Why this exists
---------------
`docs/UNSAFE.md` §4 records that Miri stopped, at the allocator trampoline, on a
class of defect Rust's strict-provenance model exists to name: a **callable pointer
reconstructed from an integer**. The authority stores `CRYPTO_malloc_fn` and its
siblings as C function pointers (`crypto/mem.c:23-25`, `crypto/mem_sec.c`); an early
revision of this crate stored the same value as a `usize` in an `AtomicUsize` and
recovered it with `transmute::<usize, Fn>`, so the recovered pointer had no
provenance and Miri refused to call it ("pointer not dereferenceable ... has no
provenance").

A one-time fix is not a regression guard. This court is the guard: it scans the
crate's Rust sources for the pattern and **fails closed** when it reappears. It is
deliberately narrow. It does not certify that every pointer is provenance-clean; it
detects the one class that is both mechanically recognisable and an observed,
reproduced blocker.

What it flags
-------------
An integer -> callable-pointer reconstruction in `src/**/*.rs`:

  * `transmute::<usize, ...>`, `transmute::<u64, ...>`, `transmute::<u32, ...>`,
    and the `transmute_copy` spelling of the same — the exact shape of the defect,
    where an integer is reinterpreted as a callable pointer that carries no
    provenance.

What it deliberately does **not** flag
--------------------------------------
  * `ptr as usize` / `ptr.addr()` used for arithmetic or identity comparison: the
    address is exposed, not discarded, and a typed pointer remains for every
    dereference (this is the alignment use in `CRYPTO_aligned_alloc`);
  * `transmute::<*mut (), Fn>`: a pointer that still carries the function's
    provenance, cast back to the function type, is the authority's own operation;
  * `ptr::with_exposed_provenance`/`from_exposed_addr`: the explicit provenance
    TCB used by the dynamic loader (`src/dso/dlfcn.rs`), recorded in `docs/UNSAFE.md`
    §4 rather than mechanised here.

Tamper proof
------------
`--self-test` runs the detector over an embedded fixture, in memory, and asserts
that it fires on the forbidden shape and stays silent on the benign one. A detector
that silently stopped matching would fail the self-test, so "it did not fire" is
never the only evidence.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"
GENERATOR = "forensics/tools/provenance_court.py"

# The integer -> pointer reconstruction, by name, for both `transmute` spellings.
_INT_TRANSMUTE = re.compile(
    r"transmute(?:_copy)?\s*::\s*<\s*(?:usize|u64|u32)\s*,"
)

# Synthetic lines the self-test runs the detector over. They are not part of the
# tree; the point is that the detector's verdict on them is a property this file
# can assert.
_SELFTEST_FORBIDDEN = (
    "fn f() -> MallocFn { let raw = slot.load(Ordering::Relaxed); "
    "unsafe { transmute::<usize, MallocFn>(raw) } }"
)
_SELFTEST_FORBIDDEN_COPY = (
    "let f = unsafe { core::mem::transmute_copy::<u64, FreeFn>(&raw) };"
)
_SELFTEST_BENIGN = (
    "fn f() -> MallocFn { let raw = slot.load(Ordering::Relaxed); "
    "unsafe { transmute::<*mut (), MallocFn>(raw) } }"
)
_SELFTEST_ALIGNMENT = "let addr = base.addr(); let off = align - (addr % align);"


def scan_text(text: str) -> list[tuple[int, str]]:
    """The forbidden patterns in `text`, as `(1-based line, pattern-name)`."""
    findings: list[tuple[int, str]] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if _INT_TRANSMUTE.search(line):
            findings.append((i, "integer-to-pointer transmute"))
    return findings


def scan_repo(root: Path = SRC) -> list[str]:
    """Every finding in `root`, as `relpath:line: pattern: source` strings."""
    out: list[str] = []
    for path in sorted(root.rglob("*.rs")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for line, pattern in scan_text(text):
            src = text.splitlines()[line - 1].strip()
            try:
                shown = path.relative_to(REPO_ROOT).as_posix()
            except ValueError:
                shown = path.as_posix()
            out.append(f"{shown}:{line}: {pattern}: {src}")
    return out


def self_test() -> int:
    """Prove the detector fires on the forbidden shapes and not the benign ones."""
    problems: list[str] = []
    for name, fixture in (
        ("transmute", _SELFTEST_FORBIDDEN),
        ("transmute_copy", _SELFTEST_FORBIDDEN_COPY),
    ):
        if not scan_text(fixture):
            problems.append(f"the detector did not fire on the {name} fixture")
    for name, fixture in (
        ("pointer transmute", _SELFTEST_BENIGN),
        ("address-only arithmetic", _SELFTEST_ALIGNMENT),
    ):
        hit = scan_text(fixture)
        if hit:
            problems.append(f"the detector fired on the benign {name} fixture: {hit}")
    # The tree-level tamper proof: a planted file must be found by the same walk
    # the court uses, so "the tree is clean" cannot be a detector that scans nothing.
    with tempfile.TemporaryDirectory() as tmp:
        planted = Path(tmp) / "tamper.rs"
        planted.write_text(_SELFTEST_FORBIDDEN, encoding="utf-8")
        if not scan_repo(Path(tmp)):
            problems.append("the tree walk did not find a planted forbidden file")
    if problems:
        for p in problems:
            print(f"[provenance-court] SELF-TEST FAIL: {p}", file=sys.stderr)
        return 1
    print("[provenance-court] self-test: fires on integer reconstructions, silent on "
          "pointer transmutes and address-only arithmetic, and finds a planted file")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="scan the tree and exit non-zero on a finding")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the detector fires on its forbidden fixture")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    findings = scan_repo()
    for f in findings:
        print(f"[provenance-court] FINDING: {f}", file=sys.stderr)
    if findings:
        print(f"[provenance-court] {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print("[provenance-court] clean: no integer->callable-pointer reconstruction in src/**/*.rs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
