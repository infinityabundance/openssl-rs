#!/usr/bin/env python3
"""Tests for forensics/tools/build_identity.py -- the `PFP-85` build-input identity.

Why these tests
---------------
The manifest is the cheap, fail-closed pre-filter in front of the reproducible
DSO digest.  Its whole value is that an identity which silently omits one input
would let a real source change through unnoticed, so the properties that make it
trustworthy are pinned here:

* the Merkle-style root is order-independent and changes when one digest or one
  path changes;
* the court-container rebase resolves ``/work/...`` onto the checkout, and an
  unresolvable or ambiguous suffix is a refusal rather than a guess;
* a synthetic cargo fixture derives exactly the declared inputs (the binary
  dep-info, ``cargo:rerun-if-changed=``/``cargo:rerun-if-env-changed=`` lines,
  the mandatory manifests) and a file named by two declarations is hashed once;
* a missing fingerprint, a missing build-script output, an empty dep-info and an
  absent manifest are each a named refusal -- never an empty "clean" set.

Every fixture is a fresh ``tempfile.mkdtemp`` tree; nothing is written inside the
real repository, so a test can never perturb the committed manifest.

Run directly (`python3 forensics/tools/tests/test_build_identity.py`) or with
`python3 -m unittest forensics.tools.tests.test_build_identity -v`.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

import build_identity  # noqa: E402


class RootTests(unittest.TestCase):
    """The Merkle root commits to every path and digest in the set."""

    def test_root_is_order_independent(self) -> None:
        one = [("b", "2"), ("a", "1")]
        other = [("a", "1"), ("b", "2")]
        self.assertEqual(build_identity._root(one), build_identity._root(other))

    def test_root_changes_with_one_digest(self) -> None:
        base = [("a", "1"), ("b", "2")]
        changed = [("a", "9"), ("b", "2")]
        self.assertNotEqual(build_identity._root(base), build_identity._root(changed))

    def test_root_changes_with_one_path(self) -> None:
        base = [("a", "1"), ("b", "2")]
        renamed = [("c", "1"), ("b", "2")]
        self.assertNotEqual(build_identity._root(base), build_identity._root(renamed))


class Fixture(unittest.TestCase):
    """A throwaway checkout under ``tempfile.mkdtemp``, never the real tree."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="build-identity-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.target = self.root / "target"

    def write(self, relative: str, text: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def cargo(self, version: str = "0.0.52") -> None:
        self.write("Cargo.toml", f'[package]\nname = "openssl-rs"\nversion = "{version}"\n')
        self.write("Cargo.lock", "version = 3\n")
        self.write("build.rs", "fn main() {}\n")
        self.write("rust-toolchain.toml", '[toolchain]\nchannel = "1.98.1"\n')
        self.write("src/lib.rs", "pub fn marker() {}\n")
        self.write("config/abi.json", "{}\n")

    def dep_info(self) -> Path:
        path = self.target / "debug" / ".fingerprint" / "openssl-rs-fixture" / "dep-lib-openssl_rs"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x00src/lib.rs\x00")
        return path

    def build_output(self, *lines: str) -> Path:
        path = self.target / "debug" / "build" / "openssl-rs-fixture" / "output"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path


class RebaseTests(Fixture):
    """Court-container paths are rebased only when the survivor is unambiguous."""

    def test_rebases_court_absolute_path(self) -> None:
        expected = self.write("docs/X.md", "x")
        self.assertEqual(build_identity._rebase(self.root, "/work/docs/X.md"), expected)

    def test_refuses_path_that_resolves_nowhere(self) -> None:
        with self.assertRaises(build_identity.Refusal) as caught:
            build_identity._rebase(self.root, "/work/docs/X.md")
        self.assertEqual(caught.exception.code, build_identity.BI_INPUT_UNREADABLE)

    def test_refuses_ambiguous_suffix(self) -> None:
        self.write("docs/X.md", "a")
        self.write("X.md", "b")
        with self.assertRaises(build_identity.Refusal) as caught:
            build_identity._rebase(self.root, "/work/docs/X.md")
        self.assertEqual(caught.exception.code, build_identity.BI_INPUT_UNREADABLE)

    def test_refuses_escaping_relative_path(self) -> None:
        with self.assertRaises(build_identity.Refusal) as caught:
            build_identity._rebase(self.root, "../outside.json")
        self.assertEqual(caught.exception.code, build_identity.BI_INPUT_UNREADABLE)


class DeriveTests(Fixture):
    """A synthetic cargo record yields exactly the declared inputs."""

    def setup_fixture(self) -> None:
        self.cargo()
        self.dep_info()
        self.build_output(
            "cargo:rerun-if-changed=/work/config/abi.json",
            "cargo:rerun-if-env-changed=OPENSSL_RS_COMPAT",
        )

    def test_derives_declared_inputs(self) -> None:
        self.setup_fixture()
        document = build_identity.derive(self.root, self.target, "debug")
        paths = {item["path"] for item in document["inputs"]}
        self.assertIn("config/abi.json", paths)
        self.assertIn("src/lib.rs", paths)
        self.assertIn("Cargo.lock", paths)
        self.assertIn("rust-toolchain.toml", paths)
        self.assertIn("<env:OPENSSL_RS_COMPAT>", paths)
        self.assertEqual(
            document["root"],
            build_identity._root([(i["path"], i["sha256"]) for i in document["inputs"]]),
        )

    def test_duplicate_declaration_is_hashed_once(self) -> None:
        self.cargo()
        self.dep_info()  # names src/lib.rs relatively
        self.build_output("cargo:rerun-if-changed=/work/src/lib.rs")  # same file, absolutely
        document = build_identity.derive(self.root, self.target, "debug")
        paths = [item["path"] for item in document["inputs"]]
        self.assertEqual(paths.count("src/lib.rs"), 1)

    def test_unresolvable_declared_input_is_refused(self) -> None:
        self.cargo()
        self.dep_info()
        self.build_output("cargo:rerun-if-changed=/work/nope/missing.json")
        with self.assertRaises(build_identity.Refusal) as caught:
            build_identity.derive(self.root, self.target, "debug")
        self.assertEqual(caught.exception.code, build_identity.BI_INPUT_UNREADABLE)

    def test_missing_fingerprint_is_refused(self) -> None:
        self.cargo()
        self.build_output("cargo:rerun-if-changed=/work/config/abi.json")
        with self.assertRaises(build_identity.Refusal) as caught:
            build_identity.derive(self.root, self.target, "debug")
        self.assertEqual(caught.exception.code, build_identity.BI_DEPINFO_MISSING)

    def test_missing_build_output_is_refused(self) -> None:
        self.cargo()
        self.dep_info()
        with self.assertRaises(build_identity.Refusal) as caught:
            build_identity.derive(self.root, self.target, "debug")
        self.assertEqual(caught.exception.code, build_identity.BI_BUILD_OUTPUT_MISSING)

    def test_empty_dep_info_is_refused(self) -> None:
        self.cargo()
        self.dep_info().write_bytes(b"")
        self.build_output("cargo:rerun-if-changed=/work/config/abi.json")
        with self.assertRaises(build_identity.Refusal) as caught:
            build_identity.derive(self.root, self.target, "debug")
        self.assertEqual(caught.exception.code, build_identity.BI_DEPINFO_MISSING)


class CheckTests(Fixture):
    """`check` refuses a tree without a manifest and detects one-input drift."""

    def test_absent_manifest_is_refused(self) -> None:
        self.cargo()
        refusals = build_identity.check(self.root, self.target, "debug")
        self.assertEqual(
            [refusal.code for refusal in refusals], [build_identity.BI_MANIFEST_MISSING]
        )

    def test_write_then_check_is_clean_and_drift_is_refused(self) -> None:
        self.cargo()
        self.dep_info()
        self.build_output(
            "cargo:rerun-if-changed=/work/config/abi.json",
            "cargo:rerun-if-env-changed=OPENSSL_RS_COMPAT",
        )
        build_identity.write(self.root, self.target, "debug")
        self.assertEqual(build_identity.check(self.root, self.target, "debug"), [])

        self.write("src/lib.rs", "pub fn changed() {}\n")
        refusals = build_identity.check(self.root, self.target, "debug")
        self.assertEqual([refusal.code for refusal in refusals], [build_identity.BI_ROOT_MISMATCH])


if __name__ == "__main__":
    unittest.main()
