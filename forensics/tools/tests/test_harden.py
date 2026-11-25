#!/usr/bin/env python3
"""Controls for A11: one strict JSON reader, and the differential that shows why.

Each control exercises one rule of `docs/PARSER-HARDENING.md`.  A control proves
that a refusal fires for the substituted form; it does not prove the form occurs
anywhere in the tree.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TOOLS))

import harden as h  # noqa: E402

A11 = REPO_ROOT / "evidence" / "a11"
SCAN = A11 / "SCAN.json"
DIFFERENTIAL = A11 / "DIFFERENTIAL.json"
CONTROLS = A11 / "CONTROLS.json"
PRODUCER = A11 / "build_evidence.py"
TOOL = TOOLS / "harden.py"
DOCUMENT = REPO_ROOT / "docs" / "PARSER-HARDENING.md"

BASE_COMMIT = "a99ddf9677229487e5cf4051031e886444a189b7"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _assert_refused(test: unittest.TestCase, code: str, raw: bytes, **bounds) -> str:
    with test.assertRaises(h.Refusal) as raised:
        h.loads(raw, **bounds)
    test.assertEqual(raised.exception.code, code, raised.exception.message)
    return raised.exception.message


class StrictReading(unittest.TestCase):
    def test_every_json_value_kind_is_accepted(self) -> None:
        self.assertEqual(h.loads(b'{"a":[1,2.5,"x",true,false,null]}'), {
            "a": [1, 2.5, "x", True, False, None]
        })

    def test_integers_and_floats_keep_their_type(self) -> None:
        value = h.loads(b'[1,1.0,-2,2e3]')
        self.assertIs(type(value[0]), int)
        self.assertIs(type(value[1]), float)
        self.assertIs(type(value[2]), int)
        self.assertIs(type(value[3]), float)

    def test_escapes_and_a_paired_surrogate_are_decoded(self) -> None:
        self.assertEqual(h.loads(b'"a\\n\\t\\"\\\\\\/"'), 'a\n\t"\\/')
        self.assertEqual(h.loads(b'"\\ud83d\\ude00"'), "\U0001f600")
        self.assertEqual(h.loads(b'"\\u00e9"'), "\u00e9")

    def test_an_empty_input_is_syntax(self) -> None:
        _assert_refused(self, h.PH_REFUSED_SYNTAX, b"")


class Refusals(unittest.TestCase):
    def test_encoding(self) -> None:
        _assert_refused(self, h.PH_REFUSED_ENCODING, b'{"a":"\xff"}')

    def test_bom_utf8(self) -> None:
        _assert_refused(self, h.PH_REFUSED_BOM, b"\xef\xbb\xbf" + b'{"a":1}')

    def test_bom_utf16(self) -> None:
        _assert_refused(self, h.PH_REFUSED_BOM, b"\xff\xfe" + b'{\x00}\x00')

    def test_duplicate_key(self) -> None:
        _assert_refused(self, h.PH_REFUSED_DUPLICATE_KEY, b'{"a":1,"a":2}')

    def test_duplicate_key_at_depth(self) -> None:
        _assert_refused(
            self, h.PH_REFUSED_DUPLICATE_KEY, b'{"a":{"b":1,"b":2}}'
        )

    def test_depth(self) -> None:
        _assert_refused(
            self, h.PH_REFUSED_DEPTH, b"[[[[1]]]]", max_depth=3
        )

    def test_size(self) -> None:
        _assert_refused(self, h.PH_REFUSED_SIZE, b"[1,2,3,4]", max_bytes=8)

    def test_nonfinite_nan(self) -> None:
        _assert_refused(self, h.PH_REFUSED_NONFINITE, b'{"a":NaN}')

    def test_nonfinite_infinity(self) -> None:
        _assert_refused(self, h.PH_REFUSED_NONFINITE, b'{"a":Infinity}')

    def test_nonfinite_negative_infinity(self) -> None:
        _assert_refused(self, h.PH_REFUSED_NONFINITE, b'{"a":-Infinity}')

    def test_nonfinite_overflow(self) -> None:
        _assert_refused(self, h.PH_REFUSED_NONFINITE, b"1e400")

    def test_trailing_data(self) -> None:
        _assert_refused(self, h.PH_REFUSED_TRAILING_DATA, b'{"a":1}{"b":2}')

    def test_trailing_scalar(self) -> None:
        _assert_refused(self, h.PH_REFUSED_TRAILING_DATA, b"1 2")

    def test_integer_range(self) -> None:
        _assert_refused(
            self, h.PH_REFUSED_INTEGER_RANGE, b"18446744073709551616"
        )

    def test_integer_range_negative(self) -> None:
        _assert_refused(
            self, h.PH_REFUSED_INTEGER_RANGE, b"-18446744073709551616"
        )

    def test_number_form_negative_zero(self) -> None:
        _assert_refused(self, h.PH_REFUSED_NUMBER_FORM, b"-0")

    def test_number_form_leading_zero(self) -> None:
        _assert_refused(self, h.PH_REFUSED_NUMBER_FORM, b"01")

    def test_number_form_leading_plus(self) -> None:
        _assert_refused(self, h.PH_REFUSED_NUMBER_FORM, b"+1")

    def test_number_form_missing_fraction(self) -> None:
        _assert_refused(self, h.PH_REFUSED_NUMBER_FORM, b"1.")

    def test_number_form_missing_integer(self) -> None:
        _assert_refused(self, h.PH_REFUSED_NUMBER_FORM, b".5")

    def test_number_form_missing_exponent(self) -> None:
        _assert_refused(self, h.PH_REFUSED_NUMBER_FORM, b"1e")

    def test_lone_high_surrogate(self) -> None:
        _assert_refused(self, h.PH_REFUSED_LONE_SURROGATE, b'"\\ud800"')

    def test_lone_low_surrogate(self) -> None:
        _assert_refused(self, h.PH_REFUSED_LONE_SURROGATE, b'"\\udc00"')

    def test_high_surrogate_followed_by_a_non_low(self) -> None:
        _assert_refused(
            self, h.PH_REFUSED_LONE_SURROGATE, b'"\\ud800\\u0041"'
        )

    def test_control_character_newline(self) -> None:
        _assert_refused(
            self, h.PH_REFUSED_CONTROL_CHARACTER, b'{"a":"x\ny"}'
        )

    def test_control_character_nul(self) -> None:
        _assert_refused(
            self, h.PH_REFUSED_CONTROL_CHARACTER, b'{"a":"x\x00y"}'
        )

    def test_key_not_text_number(self) -> None:
        _assert_refused(self, h.PH_REFUSED_KEY_NOT_TEXT, b"{1:2}")

    def test_key_not_text_bare_word(self) -> None:
        _assert_refused(self, h.PH_REFUSED_KEY_NOT_TEXT, b"{true:1}")

    def test_syntax_unterminated(self) -> None:
        _assert_refused(self, h.PH_REFUSED_SYNTAX, b'{"a":}')

    def test_syntax_trailing_comma(self) -> None:
        _assert_refused(self, h.PH_REFUSED_SYNTAX, b'{"a":1,}')

    def test_syntax_non_standard_literal(self) -> None:
        _assert_refused(self, h.PH_REFUSED_SYNTAX, b"truex")


class Boundaries(unittest.TestCase):
    def test_size_at_the_limit_and_one_past(self) -> None:
        self.assertEqual(
            h.loads(b"1234", max_bytes=4, max_depth=4, integer_bits=64), 1234
        )
        _assert_refused(
            self, h.PH_REFUSED_SIZE, b"12345", max_bytes=4, max_depth=4,
            integer_bits=64
        )

    def test_depth_at_the_limit_and_one_past(self) -> None:
        self.assertEqual(
            h.loads(b"[[[1]]]", max_bytes=4096, max_depth=3, integer_bits=64),
            [[[1]]],
        )
        _assert_refused(
            self, h.PH_REFUSED_DEPTH, b"[[[[1]]]]", max_bytes=4096,
            max_depth=3, integer_bits=64
        )

    def test_integer_bits_at_the_limit_and_one_past(self) -> None:
        self.assertEqual(
            h.loads(b"15", max_bytes=4096, max_depth=4, integer_bits=4), 15
        )
        self.assertEqual(
            h.loads(b"-15", max_bytes=4096, max_depth=4, integer_bits=4), -15
        )
        _assert_refused(
            self, h.PH_REFUSED_INTEGER_RANGE, b"16", max_bytes=4096,
            max_depth=4, integer_bits=4
        )
        _assert_refused(
            self, h.PH_REFUSED_INTEGER_RANGE, b"-16", max_bytes=4096,
            max_depth=4, integer_bits=4
        )

    def test_parameters_are_validated(self) -> None:
        for bounds in (
            {"max_bytes": -1, "max_depth": 1, "integer_bits": 1},
            {"max_bytes": 1, "max_depth": 0, "integer_bits": 1},
            {"max_bytes": 1, "max_depth": 1, "integer_bits": 0},
        ):
            with self.subTest(bounds=bounds):
                with self.assertRaises(ValueError):
                    h.loads(b"0", **bounds)

    def test_a_non_bytes_input_is_a_type_error(self) -> None:
        with self.assertRaises(TypeError):
            h.loads({"a": 1})  # type: ignore[arg-type]


class DifferentialTests(unittest.TestCase):
    def test_the_duplicate_key_pair_collapses_under_the_permissive_reader(self) -> None:
        pair = h.differential_pair(b'{"a":1,"a":2}', b'{"a":2}')
        self.assertTrue(pair["distinctBytes"])
        self.assertNotEqual(pair["firstSha256"], pair["secondSha256"])
        self.assertTrue(pair["samePermissiveValue"])
        self.assertTrue(pair["samePermissiveCanonical"])
        self.assertEqual(
            pair["first"]["strict"]["code"], h.PH_REFUSED_DUPLICATE_KEY
        )
        self.assertEqual(pair["second"]["strict"]["code"], h.CODE_OK)
        self.assertTrue(pair["first"]["duplicateKeyCollapsed"])

    def test_the_number_form_pair_collapses_negative_zero(self) -> None:
        pair = h.differential_pair(b'{"n":-0}', b'{"n":0}')
        self.assertTrue(pair["distinctBytes"])
        self.assertTrue(pair["samePermissiveValue"])
        self.assertEqual(pair["first"]["strict"]["code"], h.PH_REFUSED_NUMBER_FORM)
        self.assertEqual(pair["second"]["strict"]["code"], h.CODE_OK)

    def test_an_integer_and_a_float_are_different_types(self) -> None:
        pair = h.differential_pair(b'{"n":1}', b'{"n":1.0}')
        self.assertFalse(pair["samePermissiveValue"])
        self.assertEqual(pair["crossNumberChanges"][0]["kind"], "type")
        self.assertEqual(pair["crossNumberChanges"][0]["left"], "integer:1")
        self.assertEqual(pair["crossNumberChanges"][0]["right"], "number:1.0")
        self.assertEqual(pair["first"]["strict"]["code"], h.CODE_OK)
        self.assertEqual(pair["second"]["strict"]["code"], h.CODE_OK)

    def test_non_finite_is_accepted_only_by_the_permissive_reader(self) -> None:
        record = h.differential(b'{"n":NaN}')
        self.assertEqual(record["strict"]["code"], h.PH_REFUSED_NONFINITE)
        self.assertEqual(record["permissive"]["status"], "ACCEPTED")
        self.assertTrue(record["acceptedOnlyByPermissive"])

    def test_bom_trailing_data_and_depth_differ(self) -> None:
        bom = h.differential_pair(b"\xef\xbb\xbf" + b'{"a":1}', b'{"a":1}')
        self.assertTrue(bom["samePermissiveValue"])
        self.assertEqual(bom["first"]["strict"]["code"], h.PH_REFUSED_BOM)

        trailing = h.differential_pair(b'{"a":1}{"b":2}', b'{"a":1}')
        self.assertTrue(trailing["samePermissiveValue"])
        self.assertEqual(
            trailing["first"]["strict"]["code"], h.PH_REFUSED_TRAILING_DATA
        )

        within = h.differential(b"[" * 64 + b"1" + b"]" * 64, max_depth=64)
        past = h.differential(b"[" * 65 + b"1" + b"]" * 65, max_depth=64)
        self.assertEqual(within["strict"]["code"], h.CODE_OK)
        self.assertEqual(past["strict"]["code"], h.PH_REFUSED_DEPTH)
        self.assertEqual(past["permissive"]["status"], "ACCEPTED")

    def test_the_permissive_reader_is_explicit_and_separate(self) -> None:
        self.assertTrue(callable(h.loads_permissive))
        self.assertEqual(h.loads_permissive(b'{"a":1,"a":2}'), {"a": 2})
        with self.assertRaises(h.Refusal):
            h.loads(b'{"a":1,"a":2}')


class ScanTests(unittest.TestCase):
    def test_a_file_over_the_bound_is_reported_not_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "small.json").write_bytes(b"[1]")
            (root / "big.json").write_bytes(b"[" + b"1," * 64 + b"1]")
            result = h.scan(
                ["small.json", "big.json"], max_bytes=16, repo_root=root
            )
        self.assertEqual(result["files"], 2)
        self.assertEqual(result["examined"], 1)
        self.assertEqual(result["skippedSize"], 1)
        rows = {row["path"]: row for row in result["results"]}
        self.assertEqual(rows["small.json"]["result"], "STRICT_OK")
        self.assertEqual(rows["big.json"]["result"], "SKIPPED_SIZE")
        self.assertIn("bytes", rows["big.json"])

    def test_a_symlink_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "tree"
            root.mkdir()
            outside = Path(directory) / "outside.json"
            outside.write_bytes(b"[1]")
            (root / "link.json").symlink_to(outside)
            result = h.scan(["link.json"], repo_root=root)
        self.assertEqual(result["files"], 1)
        self.assertEqual(result["examined"], 0)
        self.assertEqual(result["results"][0]["result"], "SKIPPED_SYMLINK")

    def test_the_recorded_scan_covers_the_population(self) -> None:
        document = _load(SCAN)
        population = document["population"]
        self.assertEqual(population["binding"], h.POPULATION_FROZEN)
        self.assertEqual(population["glob"], h.SCAN_GLOB)
        members = population["members"]
        self.assertEqual(population["files"], len(members))
        self.assertEqual(document["summary"]["files"], len(members))
        self.assertEqual(len(document["results"]), len(members))
        self.assertEqual(
            [row["path"] for row in document["results"]],
            [member["path"] for member in members],
        )
        for member in members:
            with self.subTest(path=member["path"]):
                self.assertEqual(set(member), {"path", "sha256", "bytes"})
                self.assertEqual(len(member["sha256"]), 64)
                int(member["sha256"], 16)
                self.assertGreaterEqual(member["bytes"], 0)
        self.assertEqual(document["summary"]["refused"], 0)
        self.assertEqual(
            document["summary"]["strictOk"], document["summary"]["examined"]
        )
        results = [row["result"] for row in document["results"]]
        self.assertIn("STRICT_OK", results)
        self.assertIn("SKIPPED_SIZE", results)
        self.assertEqual(
            document["summary"]["skippedSize"], results.count("SKIPPED_SIZE")
        )
        for row in document["results"]:
            with self.subTest(path=row["path"]):
                self.assertIn(row["result"], ("STRICT_OK", "SKIPPED_SIZE"))
                self.assertEqual(len(row["sha256"]), 64)

    def test_the_recorded_scan_parameters_are_the_defaults(self) -> None:
        parameters = _load(SCAN)["parameters"]
        self.assertEqual(parameters["max_bytes"], h.DEFAULT_MAX_BYTES)
        self.assertEqual(parameters["max_depth"], h.DEFAULT_MAX_DEPTH)
        self.assertEqual(parameters["integer_bits"], h.DEFAULT_INTEGER_BITS)

    def test_the_frozen_record_reproduces_at_head(self) -> None:
        document = _load(SCAN)
        result = h.verify_record(document)
        self.assertTrue(
            result["matchesRecord"],
            "the rebuilt results differ from the frozen record",
        )
        members = document["population"]["members"]
        self.assertEqual(result["population"], len(members))
        self.assertEqual(result["population"], document["population"]["files"])
        self.assertEqual(result["summary"], document["summary"])
        self.assertEqual(result["results"], document["results"])
        frozen = {member["path"] for member in members}
        for entry in result["newSinceRecord"]:
            with self.subTest(path=entry["path"]):
                self.assertNotIn(entry["path"], frozen)
                self.assertEqual(entry["result"], h.RESULT_NEW_SINCE_RECORD)
                self.assertEqual(len(entry["sha256"]), 64)

    @staticmethod
    def _mirror_record(root: Path, names: tuple[str, ...]) -> tuple[dict, list[str]]:
        """A small temporary mirror of the tree, frozen through the tool."""
        (root / "evidence").mkdir(parents=True)
        for name in names:
            (root / "evidence" / name).write_bytes(b'{"x":1}')
        paths = [f"evidence/{name}" for name in names]
        members = h.freeze_population(paths, repo_root=root)
        rebuilt = h.scan_frozen_population(members, repo_root=root)
        document = {
            "schema": "openssl-rs/a11/scan/2",
            "population": {
                "binding": h.POPULATION_FROZEN,
                "glob": "evidence/*.json",
                "excludedPrefixes": [],
                "members": members,
                "files": len(members),
            },
            "parameters": rebuilt["parameters"],
            "summary": {
                key: rebuilt[key]
                for key in (
                    "files",
                    "examined",
                    "strictOk",
                    "skippedSize",
                    "skippedOther",
                    "refused",
                )
            },
            "results": rebuilt["results"],
        }
        return document, paths

    def test_growth_after_the_freeze_is_reported_not_absorbed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "mirror"
            document, paths = self._mirror_record(root, ("a.json", "b.json"))
            before = h.verify_record(document, repo_root=root, live_paths=paths)
            self.assertEqual(before["newSinceRecord"], [])
            # Append a synthetic JSON file to the mirror, never to the real tree.
            (root / "evidence" / "c.json").write_bytes(b'{"c":3}')
            after = h.verify_record(
                document,
                repo_root=root,
                live_paths=paths + ["evidence/c.json"],
            )
        self.assertEqual(after["population"], 2)
        self.assertEqual(after["summary"], document["summary"])
        self.assertEqual(after["results"], document["results"])
        self.assertEqual(
            [entry["path"] for entry in after["newSinceRecord"]],
            ["evidence/c.json"],
        )
        entry = after["newSinceRecord"][0]
        self.assertEqual(entry["result"], h.RESULT_NEW_SINCE_RECORD)
        self.assertEqual(entry["sha256"], h.sha256_bytes(b'{"c":3}'))
        self.assertEqual(entry["bytes"], 7)

    def test_a_changed_or_removed_member_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "mirror"
            document, paths = self._mirror_record(root, ("a.json", "b.json"))
            (root / "evidence" / "a.json").write_bytes(b"[1]")
            with self.assertRaises(h.Refusal) as changed:
                h.verify_record(document, repo_root=root, live_paths=paths)
            self.assertEqual(
                changed.exception.code, h.PH_REFUSED_POPULATION_DRIFT
            )
            (root / "evidence" / "a.json").write_bytes(b'{"x":1}')
            (root / "evidence" / "b.json").unlink()
            with self.assertRaises(h.Refusal) as removed:
                h.verify_record(
                    document, repo_root=root, live_paths=["evidence/a.json"]
                )
            self.assertEqual(
                removed.exception.code, h.PH_REFUSED_POPULATION_DRIFT
            )

    def test_a_live_population_is_labelled_and_not_comparable(self) -> None:
        document = {
            "schema": "openssl-rs/a11/scan/2",
            "population": {"binding": h.POPULATION_LIVE, "glob": h.SCAN_GLOB},
        }
        with self.assertRaises(h.Refusal) as raised:
            h.verify_record(document, live_paths=[])
        self.assertEqual(raised.exception.code, h.PH_REFUSED_POPULATION_DRIFT)


class CommandLine(unittest.TestCase):
    def test_parse_accepts_and_prints_the_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ok.json"
            path.write_bytes(b'{"a":[1,2]}')
            result = subprocess.run(
                [sys.executable, str(TOOL), "parse", str(path)],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(h.CODE_OK, result.stdout)

    def test_parse_refuses_exit_one_and_prints_the_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_bytes(b'{"a":1,"a":2}')
            result = subprocess.run(
                [sys.executable, str(TOOL), "parse", str(path)],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn(h.PH_REFUSED_DUPLICATE_KEY, result.stderr)

    def test_differential_exits_one_on_a_strict_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_bytes(b'{"a":1,"a":2}')
            result = subprocess.run(
                [sys.executable, str(TOOL), "differential", str(path)],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn(h.PH_REFUSED_DUPLICATE_KEY, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(document["strict"]["code"], h.PH_REFUSED_DUPLICATE_KEY)

    def test_scan_prints_the_code_and_the_counts(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "scan", "--live", h.SCAN_GLOB],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(h.CODE_OK, result.stdout)
        self.assertIn(f"population={h.POPULATION_LIVE}", result.stdout)
        self.assertIn("files=", result.stdout)
        self.assertIn("refused=0", result.stdout)

    def test_the_frozen_scan_reports_growth_at_the_frozen_count(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "scan", "--frozen", str(SCAN)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"population={h.POPULATION_FROZEN}", result.stdout)
        self.assertIn(
            f"files={_load(SCAN)['population']['files']}", result.stdout
        )
        self.assertIn("newSinceRecord=", result.stdout)
        for line in result.stderr.splitlines():
            self.assertIn(h.RESULT_NEW_SINCE_RECORD, line)

    def test_usage_errors_exit_two_and_print_a_code(self) -> None:
        for argv in (
            [sys.executable, str(TOOL)],
            [sys.executable, str(TOOL), "not-a-command"],
        ):
            with self.subTest(argv=argv[1:]):
                result = subprocess.run(
                    argv, capture_output=True, text=True, cwd=REPO_ROOT
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn(h.CODE_USAGE, result.stderr)


class Evidence(unittest.TestCase):
    def test_controls_cover_every_code_and_fire(self) -> None:
        document = _load(CONTROLS)
        codes = [control["code"] for control in document["controls"]]
        self.assertEqual(sorted(codes), sorted(h.REFUSALS))
        self.assertEqual(len(codes), len(set(codes)))
        for control in document["controls"]:
            with self.subTest(control=control["control"]):
                raw = bytes.fromhex(control["inputHex"])
                self.assertEqual(
                    h.sha256_bytes(raw), control["inputSha256"]
                )
                record = h.differential(raw, **control["parameters"])
                self.assertEqual(record["strict"]["code"], control["code"])
                self.assertEqual(control["strictResult"]["code"], control["code"])
                self.assertIn(control["code"], h.REFUSALS)

    def test_the_differential_records_the_decisive_case(self) -> None:
        document = _load(DIFFERENTIAL)
        self.assertEqual(document["decisiveCase"], "duplicateKey")
        pair = document["cases"]["duplicateKey"]["pair"]
        self.assertTrue(pair["samePermissiveValue"])
        self.assertTrue(pair["distinctBytes"])
        for name in (
            "duplicateKey",
            "numberForm",
            "nonFinite",
            "bom",
            "trailingData",
            "depth",
        ):
            with self.subTest(name=name):
                self.assertIn("pair", document["cases"][name])

    def test_the_producer_is_deterministic_and_matches_the_committed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for output in (first, second):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(PRODUCER),
                        "--out",
                        output,
                        "--source-commit",
                        BASE_COMMIT,
                    ],
                    capture_output=True,
                    text=True,
                    cwd=REPO_ROOT,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("SCAN.json", "DIFFERENTIAL.json", "CONTROLS.json"):
                with self.subTest(name=name):
                    committed = (A11 / name).read_bytes()
                    self.assertEqual((Path(first) / name).read_bytes(), committed)
                    self.assertEqual((Path(second) / name).read_bytes(), committed)

    def test_the_source_identity_is_supplied_not_read_live(self) -> None:
        for document in (_load(SCAN), _load(DIFFERENTIAL), _load(CONTROLS)):
            with self.subTest(document=document["schema"]):
                self.assertEqual(document["sourceIdentity"]["baseCommit"], BASE_COMMIT)
                tool = document["sourceIdentity"]["tool"]
                self.assertEqual(tool["path"], "forensics/tools/harden.py")
                self.assertEqual(
                    tool["sha256"], h.sha256_bytes((REPO_ROOT / tool["path"]).read_bytes())
                )


class DocumentSynchronisation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCUMENT.read_text(encoding="utf-8") if DOCUMENT.is_file() else ""

    def test_the_document_names_every_refusal_code(self) -> None:
        for code in h.REFUSALS:
            with self.subTest(code=code):
                self.assertIn(f"`{code}`", self.text)

    def test_the_document_names_every_control(self) -> None:
        for control in _load(CONTROLS)["controls"]:
            with self.subTest(control=control["control"]):
                self.assertIn(control["control"], self.text)

    def test_the_document_names_the_implementation_tests_and_evidence(self) -> None:
        for token in (
            "forensics/tools/harden.py",
            "forensics/tools/tests/test_harden.py",
            "evidence/a11/SCAN.json",
            "evidence/a11/DIFFERENTIAL.json",
            "evidence/a11/CONTROLS.json",
            "evidence/a11/build_evidence.py",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.text)

    def test_the_document_states_the_rust_parser_boundary(self) -> None:
        lowered = self.text.lower()
        self.assertIn("src/", self.text)
        self.assertIn("rust parser", lowered)
        self.assertIn("does not harden", lowered)
        self.assertIn("does not claim", lowered)

    def test_the_document_declares_not_run(self) -> None:
        self.assertIn("`NOT_RUN`", self.text)
        self.assertIn("NOT_RUN", self.text)


if __name__ == "__main__":
    unittest.main()
