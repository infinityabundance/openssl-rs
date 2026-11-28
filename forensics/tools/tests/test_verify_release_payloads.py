#!/usr/bin/env python3
"""Mutation controls for `forensics/tools/verify_release_payloads.py`.

The tool reconciles every duplicate of a release's payload identity (the API
checksum, the crate size, the endpoint, and the `packaging` copies) to the
registry's canonical value.  These controls patch the two network seams —
`_get_json` and `_served_digest` — so no network is used, then exercise the four
edges a reviewer named:

- a served digest that disagrees with the API checksum is a refusal, not a pass;
- an API response missing its checksum is a refusal, not a version to skip;
- a stale `packaging.crate_sha256` is reconciled to the served digest while the
  superseded value is preserved;
- an already-reconciled receipt reports `changed` false, so `--check` does not
  report `WOULD_CORRECT` on a fresh run of an already-verified receipt.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

import verify_release_payloads as vrp  # noqa: E402

VERSION = "0.0.99"
SERVED = "0123456789abcdef" * 4  # 64 hex chars
SIZE = 4096
STAMP = "2099-01-01T00:00:00Z"
OLD_STAMP = "2020-01-01T00:00:00Z"
ENDPOINT = f"https://crates.io/api/v1/crates/openssl-rs/{VERSION}"


def api(checksum: str | None = SERVED, crate_size: int = SIZE) -> dict:
    version: dict = {"crate_size": crate_size}
    if checksum is not None:
        version["checksum"] = checksum
    return {"version": version}


def receipt(*, crate_sha256: str | None = SERVED,
            compressed_bytes: int | None = SIZE,
            endpoint: str | None = ENDPOINT) -> dict:
    return {
        "status": "PUBLISHED",
        "packaging": {
            "crate_sha256": crate_sha256,
            "compressed_bytes": compressed_bytes,
        },
        "registry_verification": {
            "endpoint": endpoint,
            "checksum": SERVED,
            "checksum_prefix": SERVED[:8],
            "crate_size": SIZE,
            "download_sha256_recomputed": SERVED,
            "download_verification": f"RUN at {OLD_STAMP}: downloaded the payload",
            "verified_at": OLD_STAMP,
            "verified_by": "forensics/tools/verify_release_payloads.py (PFP-87)",
        },
    }


def run(receipt: dict, *, checksum: str | None = SERVED,
        crate_size: int = SIZE, served: str = SERVED, size: int = SIZE
        ) -> tuple[str, bool]:
    with mock.patch.object(vrp, "_get_json", return_value=api(checksum, crate_size)), \
         mock.patch.object(vrp, "_served_digest", return_value=(served, size)):
        return vrp.verify(VERSION, receipt, STAMP)


class MismatchedDigestIsRefused(unittest.TestCase):
    def test_served_digest_disagreeing_with_the_api_is_refused(self) -> None:
        with self.assertRaises(vrp.Refusal):
            run(receipt(), served="f" * 64)


class MissingChecksumIsRefused(unittest.TestCase):
    def test_api_without_a_checksum_is_refused(self) -> None:
        with self.assertRaises(vrp.Refusal):
            run(receipt(), checksum=None)


class StalePackagingChecksumIsReconciled(unittest.TestCase):
    def test_stale_crate_sha256_is_reconciled_and_superseded(self) -> None:
        stale = "beef" * 16
        r = receipt(crate_sha256=stale)
        line, changed = run(r)
        self.assertTrue(changed, line)
        self.assertIn("CORRECTED", line)
        self.assertEqual(r["packaging"]["crate_sha256"], SERVED)
        self.assertEqual(
            r["packaging"]["crate_sha256_superseded"]["value"], stale
        )
        # A correction re-stamps the receipt.
        self.assertEqual(r["registry_verification"]["verified_at"], STAMP)


class AlreadyCorrectReceiptIsNotRestamped(unittest.TestCase):
    def test_matching_identity_reports_ok_and_unchanged(self) -> None:
        r = receipt()
        line, changed = run(r)
        self.assertFalse(changed, line)
        self.assertIn("OK", line)
        # The timestamps are identity-independent and must not be rewritten.
        self.assertEqual(r["registry_verification"]["verified_at"], OLD_STAMP)
        self.assertEqual(
            r["registry_verification"]["download_verification"],
            f"RUN at {OLD_STAMP}: downloaded the payload",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
