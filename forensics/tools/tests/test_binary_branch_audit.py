#!/usr/bin/env python3
"""Controls for the inline-resolution mapping in ``binary_branch_audit.py``.

The audit accepts an inventory target whose out-of-line body the optimiser
removed only when the target declares ``resolves_to`` **and** the audit
re-establishes, from the artefact, every fact that makes the mapping honest:
the offset name derivation, the carrier's extent and coverage, a direct call
from the declared caller, the wrapper's constant argument at that call, and the
producer string.  These controls require each negative case to refuse with its
own reason, so that the mapping cannot silently widen what counts as resolved.

How "an existing symbol that is not the body" is detected (control (c)):
the carrier must be exactly ``symbol + inlining.suffix`` under the v0
length-prefix rule *and* the declared caller must call it directly.  A symbol
that merely exists cannot be substituted: if its name is unrelated the
derivation fails (``inline-witness-inconsistent``), and if it is derived but the
declared caller never calls it the call witness fails
(``inline-call-witness-missing``).  A caller that calls the carrier *without*
the recorded constant is the wrong call site
(``inline-constant-argument-missing``).  When the intended symbol has an
out-of-line body the mapping is not used and that body is audited.

Run directly (`python3 forensics/tools/tests/test_binary_branch_audit.py`) or
with `python3 -m unittest discover -s forensics/tools/tests -p 'test_*.py'`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
SCRIPT = REPO_ROOT / "courts" / "phase18" / "timing" / "binary_branch_audit.py"

PRODUCER = "fixture producer (cc 12.2.0)"

#: The carrier `wrap_body` (suffix `_body` of the target `wrap`), called from
#: `caller` with the one-line forwarder's constant argument `None` = zero.
MAPPED_ASM = """
    .text
    .globl caller
    .hidden caller
    .type caller,@function
caller:
    pushq $0x0
    call _RNvNtCx_2aq9wrap_body
    popq %rax
    ret
    .size caller, .-caller

    .globl _RNvNtCx_2aq9wrap_body
    .hidden _RNvNtCx_2aq9wrap_body
    .type _RNvNtCx_2aq9wrap_body,@function
_RNvNtCx_2aq9wrap_body:
    cmpl $0, %edi
    je 1f
    xorl %eax, %eax
1:
    ret
    .size _RNvNtCx_2aq9wrap_body, .-_RNvNtCx_2aq9wrap_body

    .section .rodata
    .asciz "fixture producer (cc 12.2.0)"
"""

#: The carrier exists, but `caller` calls a different function, so the intended
#: call path never reaches it.
NOT_CALLED_ASM = """
    .text
    .globl caller
    .hidden caller
    .type caller,@function
caller:
    pushq $0x0
    call other_fn
    popq %rax
    ret
    .size caller, .-caller

    .globl other_fn
    .hidden other_fn
    .type other_fn,@function
other_fn:
    ret
    .size other_fn, .-other_fn

    .globl _RNvNtCx_2aq9wrap_body
    .hidden _RNvNtCx_2aq9wrap_body
    .type _RNvNtCx_2aq9wrap_body,@function
_RNvNtCx_2aq9wrap_body:
    cmpl $0, %edi
    je 1f
    xorl %eax, %eax
1:
    ret
    .size _RNvNtCx_2aq9wrap_body, .-_RNvNtCx_2aq9wrap_body

    .section .rodata
    .asciz "fixture producer (cc 12.2.0)"
"""

#: The caller reaches the carrier but without the wrapper's constant argument.
NO_CONSTANT_ASM = """
    .text
    .globl caller
    .hidden caller
    .type caller,@function
caller:
    xorl %edi, %edi
    call _RNvNtCx_2aq9wrap_body
    ret
    .size caller, .-caller

    .globl _RNvNtCx_2aq9wrap_body
    .hidden _RNvNtCx_2aq9wrap_body
    .type _RNvNtCx_2aq9wrap_body,@function
_RNvNtCx_2aq9wrap_body:
    cmpl $0, %edi
    je 1f
    xorl %eax, %eax
1:
    ret
    .size _RNvNtCx_2aq9wrap_body, .-_RNvNtCx_2aq9wrap_body

    .section .rodata
    .asciz "fixture producer (cc 12.2.0)"
"""

#: Both the intended symbol and its carrier have out-of-line bodies.  The
#: mapping must not be used; the intended symbol is audited.
OUT_OF_LINE_ASM = """
    .text
    .globl caller
    .hidden caller
    .type caller,@function
caller:
    call _RNvNtCx_2aq4wrap
    ret
    .size caller, .-caller

    .globl _RNvNtCx_2aq4wrap
    .hidden _RNvNtCx_2aq4wrap
    .type _RNvNtCx_2aq4wrap,@function
_RNvNtCx_2aq4wrap:
    cmpl $0, %edi
    je 1f
    xorl %eax, %eax
1:
    ret
    .size _RNvNtCx_2aq4wrap, .-_RNvNtCx_2aq4wrap

    .globl _RNvNtCx_2aq9wrap_body
    .hidden _RNvNtCx_2aq9wrap_body
    .type _RNvNtCx_2aq9wrap_body,@function
_RNvNtCx_2aq9wrap_body:
    ret
    .size _RNvNtCx_2aq9wrap_body, .-_RNvNtCx_2aq9wrap_body

    .section .rodata
    .asciz "fixture producer (cc 12.2.0)"
"""

PREREQUISITES = shutil.which("cc") is not None and shutil.which("objdump") is not None


def build(directory: Path, name: str, asm: str) -> Path:
    source = directory / f"{name}.S"
    source.write_text(asm, encoding="utf-8")
    out = directory / f"{name}.so"
    completed = subprocess.run(
        ["cc", "-shared", "-nostdlib", "-o", str(out), str(source)],
        capture_output=True, text=True, timeout=120,
    )
    if completed.returncode != 0:
        raise unittest.SkipTest(f"cc could not build {name}.so: {completed.stderr[:200]}")
    return out


def mapping_entry(**overrides: str) -> dict:
    inlining = {
        "suffix": "_body",
        "caller": "caller",
        "constant_argument": "push $0x0",
        "producer": PRODUCER,
        "check": "fixture: wrap is a one-line forwarder to wrap_body(.., None)",
    }
    inlining.update(overrides.pop("inlining", {}))
    entry = {
        "family": "fixture core",
        "symbol": "wrap",
        "resolves_to": "wrap_body",
        "inlining": inlining,
    }
    entry.update(overrides)
    return entry


@unittest.skipUnless(PREREQUISITES, "cc and objdump are required")
class InlineMappingControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="branch-audit-inline-")
        cls.directory = Path(cls.tmp.name)
        cls.mapped = build(cls.directory, "mapped", MAPPED_ASM)
        cls.not_called = build(cls.directory, "not-called", NOT_CALLED_ASM)
        cls.no_constant = build(cls.directory, "no-constant", NO_CONSTANT_ASM)
        cls.out_of_line = build(cls.directory, "out-of-line", OUT_OF_LINE_ASM)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def inventory(self, entries: list[dict]) -> Path:
        self._seq = getattr(self, "_seq", 0) + 1
        path = self.directory / f"targets-{self._seq}.json"
        path.write_text(json.dumps(entries) + "\n", encoding="utf-8")
        return path

    def run_audit(self, entries: list[dict], dso: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--no-cpuid-scan",
             "--targets-file", str(self.inventory(entries)), str(dso)],
            capture_output=True, text=True, timeout=300,
        )

    def assert_refused(self, completed, reason: str) -> None:
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn(f"reason={reason}", completed.stderr)
        self.assertIn("FAIL-CLOSED", completed.stderr)

    # (0) the admitted case: both names are reported and the carrier is audited.
    def test_a_verified_mapping_is_audited_and_records_both_names(self) -> None:
        completed = self.run_audit([mapping_entry()], self.mapped)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("1 expected targets", completed.stderr)
        self.assertIn("audited through a verified inline mapping: 1", completed.stdout)
        self.assertIn("(carries `wrap`)", completed.stdout)
        self.assertIn("_RNvNtCx_2aq9wrap_body", completed.stdout)
        self.assertIn("**verified, audited**", completed.stdout)
        self.assertIn("`push $0x0`", completed.stdout)

    # (a) resolves_to names a symbol that does not exist.
    def test_missing_carrier_is_refused(self) -> None:
        entry = mapping_entry(resolves_to="wrap_ghost",
                              inlining={"suffix": "_ghost"})
        self.assert_refused(self.run_audit([entry], self.mapped),
                            "inline-carrier-missing")

    # see also test_wrong_existing_symbol_is_refused below.

    # (b) no resolves_to and a missing symbol: refused as before.
    def test_unmapped_missing_symbol_still_refuses(self) -> None:
        entry = {"family": "fixture core", "symbol": "wrap"}
        self.assert_refused(self.run_audit([entry], self.mapped), "missing")

    # (c1) resolves_to names an unrelated *existing* symbol.
    def test_wrong_existing_symbol_is_refused(self) -> None:
        entry = mapping_entry(resolves_to="caller")
        self.assert_refused(self.run_audit([entry], self.mapped),
                            "inline-witness-inconsistent")

    # (c2) the derived name exists but the declared caller never calls it.
    def test_carrier_the_caller_never_reaches_is_refused(self) -> None:
        self.assert_refused(self.run_audit([mapping_entry()], self.not_called),
                            "inline-call-witness-missing")

    # (c3) the caller reaches the carrier without the wrapper's constant.
    def test_call_site_without_the_constant_is_refused(self) -> None:
        self.assert_refused(self.run_audit([mapping_entry()], self.no_constant),
                            "inline-constant-argument-missing")

    # The producer string is bound to the artefact, not to the inventory.
    def test_producer_absent_from_the_dso_is_refused(self) -> None:
        entry = mapping_entry(inlining={"producer": "a compiler that built another DSO"})
        self.assert_refused(self.run_audit([entry], self.mapped),
                            "inline-producer-absent")

    # With an out-of-line body the mapping is not used; the intended symbol is
    # audited and the report says so.
    def test_out_of_line_body_wins_over_the_mapping(self) -> None:
        completed = self.run_audit([mapping_entry()], self.out_of_line)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("_RNvNtCx_2aq4wrap` @", completed.stdout)
        self.assertIn("not used (out-of-line body present)", completed.stdout)
        self.assertNotIn("(carries `wrap`)", completed.stdout)

    # A mapping must carry its justification; a bare resolves_to is a usage
    # error, not an admission.
    def test_resolves_to_without_evidence_is_a_usage_error(self) -> None:
        entry = {"family": "fixture core", "symbol": "wrap",
                 "resolves_to": "wrap_body"}
        completed = self.run_audit([entry], self.mapped)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("'inlining' must have exactly", completed.stderr)

    # Unknown fields are refused rather than ignored.
    def test_unknown_inlining_field_is_a_usage_error(self) -> None:
        entry = mapping_entry()
        entry["inlining"]["note"] = "unchecked"
        completed = self.run_audit([entry], self.mapped)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("'inlining' must have exactly", completed.stderr)

    # The suffix must be the real offset name, not a way to accept any symbol.
    def test_suffix_that_does_not_name_the_carrier_is_refused(self) -> None:
        entry = mapping_entry(resolves_to="wrap_body", inlining={"suffix": "_wrong"})
        self.assert_refused(self.run_audit([entry], self.mapped),
                            "inline-witness-inconsistent")


if __name__ == "__main__":
    unittest.main()
