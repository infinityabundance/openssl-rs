#!/usr/bin/env python3
"""PFP-64: run the crate's committed RFC 8452 AES-GCM-SIV vectors (CT-CIPHER)
against the shipped candidate DSO, and record the per-vector result.

The probe is `courts/phase8/ct_cipher.c`; the vectors are the `gcm_siv` family
mirrored from the pinned corpus's `evpciph_aes_gcm_siv.txt` ("RFC8452
AES-GCM-SIV").  The candidate directory is assembled by the caller and points
at the same DSO the instruction audit used.
"""
import json
import sys
from pathlib import Path

ROOT = Path("/work")
sys.path.insert(0, str(ROOT / "forensics" / "tools"))

import correctness_vectors as cv  # noqa: E402


def main() -> int:
    candidate = ROOT / "court" / "tmp" / "pfp64" / "candidate"
    work = ROOT / "court" / "tmp" / "pfp64" / "work"
    record = cv.run_cipher_court(
        "CT-CIPHER",
        ("gcm_siv",),
        candidate_dir=candidate,
        work_dir=work,
    )
    out = ROOT / "evidence/performance-frontier/campaigns/PFP-64/raw/ct-cipher-gcm-siv.json"
    out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"court={record.get('court')} verdict={record.get('verdict')} "
        f"checked={record.get('vectors_checked')} passed={record.get('vectors_passed')} "
        f"failed={record.get('vectors_failed')}"
    )
    if record.get("failures"):
        for failure in record["failures"][:5]:
            print(f"  FAIL {failure.get('id')} {failure.get('cipher')}")
    return 0 if record.get("verdict") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
