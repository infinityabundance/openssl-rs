#!/usr/bin/env python3
"""Mutation controls for `courts/performance-frontier/baseline/analyse_bench_api.py`.

Each control constructs a malformed campaign population and asserts the exact
refusal identifier fires: identity population, repetition ordering, correctness
check population, cross-verification population, and strict JSON loading. The
positive control reconstructs a small well-formed campaign end to end.

Run directly (`python3 forensics/tools/tests/test_analyse_bench_api.py`) or with
`python3 -m unittest discover -s forensics/tools/tests -p 'test_analyse_*.py'`.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
BASELINE = REPO_ROOT / "courts/performance-frontier/baseline"
sys.path.insert(0, str(BASELINE))

import analyse_bench_api as aba  # noqa: E402

ANALYSER = BASELINE / "analyse_bench_api.py"
SUBJECTS = ("candidate", "authority")


def preregistration() -> dict:
    return {
        "campaign": "PFP-0",
        "cross_verification_repetitions": ["00", "01"],
        "ordering": {
            "authority_first_blocks": 1,
            "candidate_first_blocks": 1,
            "kind": "balanced pseudo-random within each repetition",
            "realised_file": "raw/run-order.tsv",
            "seed": "0x50465030",
        },
        "repetitions": 2,
    }


def order_rows() -> list[dict]:
    return [
        {"repetition": "00", "first": "candidate", "second": "authority"},
        {"repetition": "01", "first": "authority", "second": "candidate"},
    ]


def identity_rows() -> list[dict]:
    rows = []
    for label, subject in aba.expected_identity_population(preregistration()):
        digest = "1" * 64 if subject == "candidate" else "2" * 64
        inode = "10" if subject == "candidate" else "20"
        rows.append(
            {
                "label": label,
                "subject": subject,
                "dso_sha256": digest,
                "expected_realpath": "/opt/libcrypto.so.3",
                "reported_realpath": "/opt/libcrypto.so.3",
                "expected_dev": "57",
                "reported_dev": "57",
                "expected_ino": inode,
                "reported_ino": inode,
                "maps_entries": "3",
                "status": "ok",
            }
        )
    return rows


def cross_rows() -> list[dict]:
    rows = []
    for rep in ("00", "01"):
        rows.append(
            {
                "repetition": rep,
                "signer": "candidate",
                "verifier": "authority",
                "verified": "1",
                "public_key": "ab" * 32,
            }
        )
        rows.append(
            {
                "repetition": rep,
                "signer": "authority",
                "verifier": "candidate",
                "verified": "1",
                "public_key": "ab" * 32,
            }
        )
    return rows


def assert_refusal(test: unittest.TestCase, rule: str, fragment: str, call) -> None:
    with test.assertRaises(aba.CampaignRefusal) as caught:
        call()
    test.assertEqual(caught.exception.rule, rule, caught.exception)
    test.assertIn(fragment, caught.exception.detail, caught.exception)


class PopulationControls(unittest.TestCase):
    def test_identity_population_is_exact(self) -> None:
        aba.check_identity_population(preregistration(), identity_rows())

    def test_missing_identity_is_refused(self) -> None:
        rows = identity_rows()
        rows.pop()
        assert_refusal(
            self,
            "PFP_IDENTITY_POPULATION",
            "missing=",
            lambda: aba.check_identity_population(preregistration(), rows),
        )

    def test_duplicated_identity_is_refused(self) -> None:
        rows = identity_rows()
        rows.append(copy.deepcopy(rows[1]))
        assert_refusal(
            self,
            "PFP_IDENTITY_POPULATION",
            "duplicated=",
            lambda: aba.check_identity_population(preregistration(), rows),
        )

    def test_substituted_identity_is_refused(self) -> None:
        rows = identity_rows()
        rows[0]["subject"] = "authority"
        assert_refusal(
            self,
            "PFP_IDENTITY_POPULATION",
            "substituted=",
            lambda: aba.check_identity_population(preregistration(), rows),
        )

    def test_extra_identity_is_refused(self) -> None:
        rows = identity_rows()
        extra = copy.deepcopy(rows[0])
        extra["label"] = "extra-process"
        rows.append(extra)
        assert_refusal(
            self,
            "PFP_IDENTITY_POPULATION",
            "extra=",
            lambda: aba.check_identity_population(preregistration(), rows),
        )

    def test_order_is_exact(self) -> None:
        aba.check_order(preregistration(), order_rows())

    def test_duplicate_repetition_is_refused(self) -> None:
        order = order_rows()
        order[1]["repetition"] = "00"
        assert_refusal(
            self,
            "PFP_ORDERING_IDENTITY",
            "duplicated=",
            lambda: aba.check_order(preregistration(), order),
        )

    def test_missing_repetition_is_refused(self) -> None:
        assert_refusal(
            self,
            "PFP_ORDERING_IDENTITY",
            "missing=",
            lambda: aba.check_order(preregistration(), order_rows()[:1]),
        )

    def test_substituted_repetition_is_refused(self) -> None:
        order = order_rows()
        order[1]["repetition"] = "99"
        assert_refusal(
            self,
            "PFP_ORDERING_IDENTITY",
            "extra=",
            lambda: aba.check_order(preregistration(), order),
        )

    def test_repetition_must_be_one_pair(self) -> None:
        order = order_rows()
        order[0]["second"] = "candidate"
        assert_refusal(
            self,
            "PFP_ORDERING_PAIR",
            "not one candidate/authority pair",
            lambda: aba.check_order(preregistration(), order),
        )

    def test_realised_balance_is_checked_per_repetition(self) -> None:
        order = order_rows()
        order[1]["first"] = "candidate"
        order[1]["second"] = "authority"
        assert_refusal(
            self,
            "PFP_ORDERING_BALANCE",
            "candidate_first=2",
            lambda: aba.check_order(preregistration(), order),
        )

    def test_declared_balance_must_be_balanced(self) -> None:
        declared = preregistration()
        declared["ordering"]["candidate_first_blocks"] = 2
        declared["ordering"]["authority_first_blocks"] = 0
        assert_refusal(
            self,
            "PFP_ORDERING_BALANCE",
            "not balanced",
            lambda: aba.check_order(declared, order_rows()),
        )

    def test_check_population_is_exact(self) -> None:
        aba.check_check_population(
            "00", "candidate", ["alpha", "beta"], {"alpha": 1, "beta": 1}
        )

    def test_empty_check_side_is_refused(self) -> None:
        assert_refusal(
            self,
            "PFP_CHECK_POPULATION",
            "no CHECK lines",
            lambda: aba.check_check_population(
                "00", "candidate", [], {"alpha": 1, "beta": 1}
            ),
        )

    def test_missing_check_identifier_is_refused(self) -> None:
        assert_refusal(
            self,
            "PFP_CHECK_POPULATION",
            "missing=['beta']",
            lambda: aba.check_check_population(
                "00", "candidate", ["alpha"], {"alpha": 1, "beta": 1}
            ),
        )

    def test_duplicated_check_identifier_is_refused(self) -> None:
        assert_refusal(
            self,
            "PFP_CHECK_POPULATION",
            "duplicated=['alpha']",
            lambda: aba.check_check_population(
                "00", "candidate", ["alpha", "alpha", "beta"], {"alpha": 1, "beta": 1}
            ),
        )

    def test_extra_check_identifier_is_refused(self) -> None:
        assert_refusal(
            self,
            "PFP_CHECK_POPULATION",
            "extra=['gamma']",
            lambda: aba.check_check_population(
                "00", "candidate", ["alpha", "beta", "gamma"], {"alpha": 1, "beta": 1}
            ),
        )

    def test_cross_population_is_exact(self) -> None:
        aba.check_cross_population(preregistration(), cross_rows())

    def test_missing_cross_direction_is_refused(self) -> None:
        rows = cross_rows()[:-1]
        assert_refusal(
            self,
            "PFP_CROSS_POPULATION",
            "missing=",
            lambda: aba.check_cross_population(preregistration(), rows),
        )

    def test_duplicated_cross_pair_is_refused(self) -> None:
        rows = cross_rows()
        rows.append(copy.deepcopy(rows[0]))
        assert_refusal(
            self,
            "PFP_CROSS_POPULATION",
            "duplicated=",
            lambda: aba.check_cross_population(preregistration(), rows),
        )

    def test_substituted_cross_direction_is_refused(self) -> None:
        rows = cross_rows()
        rows[0]["verifier"] = "candidate"
        assert_refusal(
            self,
            "PFP_CROSS_POPULATION",
            "substituted=",
            lambda: aba.check_cross_population(preregistration(), rows),
        )


class JsonControls(unittest.TestCase):
    def _load(self, text: str):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "doc.json"
            path.write_text(text, encoding="utf-8")
            return aba.load_json_strict(path)

    def test_duplicate_key_is_refused_with_path(self) -> None:
        with self.assertRaises(aba.CampaignRefusal) as caught:
            self._load('{"workloads": [], "workloads": []}')
        self.assertEqual(caught.exception.rule, "PFP_JSON_DUPLICATE_KEY")
        self.assertIn("$/workloads", caught.exception.detail)

    def test_non_finite_number_is_refused_with_path(self) -> None:
        with self.assertRaises(aba.CampaignRefusal) as caught:
            self._load('{"population": {"n": NaN}}')
        self.assertEqual(caught.exception.rule, "PFP_JSON_NON_FINITE")
        self.assertIn("$/population/n", caught.exception.detail)

    def test_infinite_number_is_refused(self) -> None:
        with self.assertRaises(aba.CampaignRefusal) as caught:
            self._load('{"n": -Infinity}')
        self.assertEqual(caught.exception.rule, "PFP_JSON_NON_FINITE")

    def test_overflowing_number_is_refused(self) -> None:
        with self.assertRaises(aba.CampaignRefusal) as caught:
            self._load('{"n": 1e999}')
        self.assertEqual(caught.exception.rule, "PFP_JSON_NON_FINITE")
        self.assertIn("$/n", caught.exception.detail)

    def test_valid_document_loads(self) -> None:
        self.assertEqual(self._load('{"a": 1, "b": [true]}'), {"a": 1, "b": [True]})


def write_campaign(root: Path) -> tuple[Path, Path, Path]:
    work = root / "campaign"
    raw = work / "raw"
    raw.mkdir(parents=True)
    workloads = root / "workloads.json"
    workloads.write_text(
        json.dumps(
            {
                "schema": "openssl-rs/performance/workloads/v1",
                "campaign": "PFP-0",
                "population_policy": {"result_lines_per_process": 1},
                "workloads": [
                    {
                        "id": "alpha",
                        "check_line_count_per_process": 1,
                        "result_line_count_per_process": 1,
                    },
                    {
                        "id": "beta",
                        "check_line_count_per_process": 1,
                        "result_line_count_per_process": 1,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    (work / "preregistration.json").write_text(
        json.dumps(preregistration()), encoding="utf-8"
    )
    (work / "build-identity.json").write_text(
        json.dumps(
            {
                "source": {"commit": "a" * 40, "branch": "staging"},
                "artefacts": {
                    "distribution_dso": {
                        "path": "/nonexistent/candidate.so",
                        "sha256": "1" * 64,
                    },
                    "authority_dso": {
                        "path": "/nonexistent/authority.so",
                        "sha256": "2" * 64,
                    },
                },
                "harness": [],
                "tools": [],
                "shell_generation": None,
            }
        ),
        encoding="utf-8",
    )
    (raw / "run-order.tsv").write_text(
        "".join(
            f"{row['repetition']}\t{row['first']}\t{row['second']}\n"
            for row in order_rows()
        ),
        encoding="utf-8",
    )
    columns = [
        "label",
        "subject",
        "dso_sha256",
        "expected_realpath",
        "reported_realpath",
        "expected_dev",
        "reported_dev",
        "expected_ino",
        "reported_ino",
        "maps_entries",
        "status",
    ]
    (raw / "identity-check.tsv").write_text(
        "\t".join(columns)
        + "\n"
        + "".join(
            "\t".join(str(row[column]) for column in columns) + "\n"
            for row in identity_rows()
        ),
        encoding="utf-8",
    )
    for rep in ("00", "01"):
        for subject in SUBJECTS:
            results = [
                "LIB /opt/libcrypto.so.3",
                "LOADED realpath=/opt/libcrypto.so.3 dev=57 ino=1 size=100",
            ]
            for name, value in (("alpha", "10.0"), ("beta", "20.0")):
                results.append(
                    f"RESULT {name} median_us={value} min_us={value} "
                    f"max_us={value} spread=0.0 iters=5 runs=5"
                )
            (raw / f"rep-{rep}-{subject}.out").write_text(
                "\n".join(results) + "\n", encoding="utf-8"
            )
            (raw / f"rep-{rep}-{subject}.check").write_text(
                "CHECK alpha hex=00\nCHECK beta hex=11\n", encoding="utf-8"
            )
    for subject in SUBJECTS:
        (raw / f"alloc-{subject}.out").write_text(
            "ALLOC alpha allocs_per_op=1.0 malloc_per_op=1.0 iters=5\n"
            "ALLOC beta allocs_per_op=2.0 malloc_per_op=2.0 iters=5\n",
            encoding="utf-8",
        )
    (work / "cross-verification.tsv").write_text(
        "repetition\tsigner\tverifier\tverified\tpublic_key\n"
        + "".join(
            f"{row['repetition']}\t{row['signer']}\t{row['verifier']}\t"
            f"{row['verified']}\t{row['public_key']}\n"
            for row in cross_rows()
        ),
        encoding="utf-8",
    )
    (work / "venue.txt").write_text(
        "court_image=test\nkernel=test\ncpu_model=test\n"
        "cgroup_memory_max=1\ncgroup_cpu_max=1\ntaskset_cpu=1\n",
        encoding="utf-8",
    )
    (raw / "pmu-probe.txt").write_text("probe\n", encoding="utf-8")
    (raw / "pmu-perf.txt").write_text("cpu_event_source=absent\n", encoding="utf-8")
    return work, workloads, root / "results.json"


class CampaignCliControls(unittest.TestCase):
    def _run(self, mutate=None) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, workloads, out = write_campaign(root)
            if mutate is not None:
                mutate(work, root)
            return subprocess.run(
                [
                    sys.executable,
                    str(ANALYSER),
                    "--work",
                    str(work),
                    "--workloads",
                    str(workloads),
                    "--out",
                    str(out),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_well_formed_campaign_is_accepted(self) -> None:
        completed = self._run()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("results:", completed.stdout)

    def _assert_failure(self, completed, rule: str, fragment: str) -> None:
        self.assertEqual(completed.returncode, 1)
        self.assertIn(rule, completed.stderr)
        self.assertIn(fragment, completed.stderr)

    def test_cli_refuses_duplicated_identity(self) -> None:
        def mutate(work: Path, root: Path) -> None:
            path = work / "raw/identity-check.tsv"
            lines = path.read_text().splitlines()
            path.write_text("\n".join(lines + [lines[1]]) + "\n", encoding="utf-8")

        self._assert_failure(
            self._run(mutate), "PFP_IDENTITY_POPULATION", "duplicated="
        )

    def test_cli_refuses_duplicated_repetition(self) -> None:
        def mutate(work: Path, root: Path) -> None:
            path = work / "raw/run-order.tsv"
            path.write_text(
                "00\tcandidate\tauthority\n00\tauthority\tcandidate\n",
                encoding="utf-8",
            )

        self._assert_failure(self._run(mutate), "PFP_ORDERING_IDENTITY", "duplicated=")

    def test_cli_refuses_empty_check_side(self) -> None:
        def mutate(work: Path, root: Path) -> None:
            (work / "raw/rep-00-candidate.check").write_text("", encoding="utf-8")
            (work / "raw/rep-00-authority.check").write_text("", encoding="utf-8")

        self._assert_failure(self._run(mutate), "PFP_CHECK_POPULATION", "no CHECK")

    def test_cli_refuses_missing_check_identifier(self) -> None:
        def mutate(work: Path, root: Path) -> None:
            for subject in SUBJECTS:
                (work / f"raw/rep-00-{subject}.check").write_text(
                    "CHECK alpha hex=00\n", encoding="utf-8"
                )

        self._assert_failure(self._run(mutate), "PFP_CHECK_POPULATION", "beta")

    def test_cli_refuses_substituted_cross_direction(self) -> None:
        def mutate(work: Path, root: Path) -> None:
            path = work / "cross-verification.tsv"
            lines = path.read_text().splitlines()
            fields = lines[1].split("\t")
            fields[2] = "candidate"
            lines[1] = "\t".join(fields)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        self._assert_failure(self._run(mutate), "PFP_CROSS_POPULATION", "substituted=")

    def test_cli_refuses_duplicate_json_key(self) -> None:
        def mutate(work: Path, root: Path) -> None:
            path = work / "preregistration.json"
            text = path.read_text()
            path.write_text(
                text.replace(
                    '"campaign": "PFP-0"',
                    '"campaign": "PFP-0", "campaign": "PFP-0"',
                ),
                encoding="utf-8",
            )

        self._assert_failure(self._run(mutate), "PFP_JSON_DUPLICATE_KEY", "$/campaign")

    def test_cli_refuses_non_finite_json(self) -> None:
        def mutate(work: Path, root: Path) -> None:
            path = work / "preregistration.json"
            text = path.read_text().replace('"repetitions": 2', '"repetitions": NaN')
            path.write_text(text, encoding="utf-8")

        self._assert_failure(self._run(mutate), "PFP_JSON_NON_FINITE", "$/repetitions")


if __name__ == "__main__":
    unittest.main(verbosity=2)
