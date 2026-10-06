#!/usr/bin/env python3
"""openssl-rs — acquire the official OpenSSL vulnerability records (Phase 23.14).

23.14 is "the security lineage": the historical vulnerabilities of the OpenSSL release
lineage, each observed and never reintroduced. Its primary source is upstream's own
vulnerability index and the per-advisory text, and the rule `docs/SECURITY_DIVERGENCE_POLICY.md`
section 1 fixes is that a *fact about a vulnerability* must be read from that source, never
typed.

This module is the **acquisition** half, and it is deliberately separate from the generator:

  * it fetches, from the official OpenSSL vulnerability pages, the consolidated index
    (`https://openssl-library.org/news/vulnerabilities/`) and, for each observed
    vulnerability, the advisory text it links to; and
  * it freezes them into one committed snapshot, `forensics/multitrack/security-source.json`,
    recording for the index and every advisory the **URL**, the **fetch date** and the
    **SHA-256 of the bytes fetched**.

The generator (`forensics/tools/security_lineage.py`) reads only that committed snapshot, so a
live website change cannot alter a reproduced result: a plane is only reproduced from the
snapshot, and the snapshot by construction names the bytes it saw (the same discipline
`forensics/tools/authority_catalog.py` applies to the release timeline).

Which vulnerabilities are observed
----------------------------------
The index currently records ~297 CVE records. This subphase does not claim to have bound every
one of them: it binds a **documented selection** -- the ten advisories below -- chosen so the
observed set spans every severity class, every maintained branch the catalogue carries
(`1.0.2`, `1.1.1`, `3.0` through `3.6`, `4.0`), and both the public and the premium
(extended-support) fix identifiers, and so the candidate-disposition derivation has at least one
vulnerability in each of its classes. The references the plane did not bind are recorded as the
snapshot's `all_references` list and surface as the court's property findings; the rest are
*unresolved*, never fabricated. Widening the selection is a matter of adding references here and
re-running this tool and the generator; it is not a change to the schema or the court.

Outputs
-------
  forensics/multitrack/security-source.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import html
import json
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT, rel, write_json  # noqa: E402

OUT = REPO_ROOT / "forensics" / "multitrack" / "security-source.json"
INDEX_URL = "https://openssl-library.org/news/vulnerabilities/"
SCHEMA = "openssl-rs/security-source/v1"
FETCH_DATE = "2026-10-06"
RETRIEVED_WITH = "python3 urllib.request (User-Agent openssl-rs-security-acquire/1)"

# The observed selection. Each reference is a public CVE upstream's index records; the advisory
# text and index entry are read from the source, never typed. The set is the coverage boundary
# this subphase binds, and the index's full CVE list is recorded beside it so the gap is counted.
OBSERVED_REFERENCES: tuple[str, ...] = (
    "CVE-2022-0778",    # High,  crypto/bn (BN_mod_sqrt), 3.0.2 / 1.1.1n / 1.0.2zd
    "CVE-2022-2068",    # Moderate, apps/c_rehash, 3.0.4 / 1.1.1p / 1.0.2zf
    "CVE-2023-0286",    # High,  crypto/x509 (X.400 GeneralName), 3.0.8 / 1.1.1t / 1.0.2zg
    "CVE-2024-0727",    # Low,   crypto/pkcs12, 3.2.1 / 3.1.5 / 3.0.13 / 1.1.1x / 1.0.2zj
    "CVE-2024-9143",    # Low,   crypto/bn (GF(2^m)), 3.3.3 / 3.2.4 / 3.1.8 / 3.0.16 / 1.1.1zb
    "CVE-2024-13176",   # Low,   crypto/ec (ECDSA timing), 3.4.1 ... / 1.1.1zb / 1.0.2zl
    "CVE-2025-15467",   # High,  crypto/cms, 3.6.1 / 3.5.5 / 3.4.4 / 3.3.6 / 3.0.19
    "CVE-2026-63072",   # Moderate, crypto/cms, 4.0.2 / 3.6.4 / 3.5.8 / 3.4.7 / 3.0.22 / 1.1.1zi
    "CVE-2026-84782",   # High,  ssl/dtls, 4.0.3 / 3.6.5 / 3.5.9 / 3.4.8 / 3.0.23 / ...
    "CVE-2026-34180",   # Low,   crypto/asn1, 4.0.1 / 3.6.3 / 3.5.7 / 3.4.6 / 3.0.21 / ...
)

_MONTHS = {
    "January": 1, "February": 2, "March": 3, "April": 4, "May": 5, "June": 6,
    "July": 7, "August": 8, "September": 9, "October": 10, "November": 11, "December": 12,
}
_CVE = re.compile(r"^CVE-\d{4}-\d{3,7}$")
_HEADING = re.compile(r'<a href="#(CVE-\d{4}-\d{3,7})">\s*<h3 id="\1">.*?</h3>\s*</a>')
_ADVISORY = re.compile(r"^https?://(?:www\.)?openssl(?:-library)?\.org/news/secadv/")


def fetch(url: str) -> bytes:
    """The bytes at `url`, with a deterministic User-Agent; never a browser render."""
    req = urllib.request.Request(url, headers={"User-Agent": "openssl-rs-security-acquire/1"})
    with urllib.request.urlopen(req, timeout=60) as response:  # noqa: S310 (fixed https URLs)
        return response.read()


def text(fragment: str) -> str:
    """A fragment's text, HTML-unescaped and whitespace-collapsed."""
    fragment = re.sub(r"<[^>]+>", " ", fragment)
    return html.unescape(re.sub(r"\s+", " ", fragment)).strip()


def _field(block: str, name: str) -> str | None:
    m = re.search(
        r'<div><span class="font-semibold">' + re.escape(name) + r'</span></div>\s*'
        r'<div class="col-span-5[^"]*">(.*?)</div>', block, re.S)
    return text(m.group(1)) if m else None


def _iso_date(raw: str | None) -> str | None:
    """`15 March 2022` -> `2022-03-15`; anything else is refused rather than guessed."""
    if not raw:
        return None
    m = re.match(r"^(\d{1,2}) ([A-Z][a-z]+) (\d{4})$", raw.strip())
    if m is None or m.group(2) not in _MONTHS:
        return None
    return datetime.date(int(m.group(3)), _MONTHS[m.group(2)], int(m.group(1))).isoformat()


def parse_index(raw: str) -> dict[str, dict]:
    """Every CVE record the index carries, keyed by reference.

    The index is a sequence of `<a href="#CVE-..."><h3 id="CVE-...">...</h3></a>` headings, each
    followed by a grid of typed fields (`Severity`, `Published at`, `Title`, `Found by`), an
    `Affected` list of `from <series> before <fixed>` ranges, and a `References` list naming the
    CVE record, the OpenSSL advisory and one git commit per fixed release. The parser reads those
    fields and nothing else: a record whose fields are shaped differently is simply not decoded.
    """
    parts = _HEADING.split(raw)
    records: dict[str, dict] = {}
    for i in range(1, len(parts) - 1, 2):
        reference, block = parts[i], parts[i + 1]
        affected = [text(a) for a in re.findall(r"<li>(from [^<]+)</li>", block)]
        refs = re.findall(r'<a href="([^"]+)"[^>]*>([^<]+)</a>', block)
        commits = {t.replace(" git commit", ""): u for u, t in refs if "git commit" in t}
        advisory = next((u for u, t in refs if t == "OpenSSL Advisory"), None)
        cve_url = next((u for u, t in refs if t == "CVE Record"), None)
        fips = re.search(r"<p>(FIPS [Ii]mpact:.*?)</p>", block, re.S)
        issue = re.search(r"<p>(Issue summary:.*?)</p>", block, re.S)
        cwe = re.search(r"<p>(CWE:\s*.*?)</p>", block, re.S)
        records[reference] = {
            "severity": _field(block, "Severity"),
            "published_raw": _field(block, "Published at"),
            "title": _field(block, "Title"),
            "found_by": _field(block, "Found by"),
            "affected": affected,
            "commit_urls": commits,
            "advisory_url": advisory,
            "cve_url": cve_url,
            "issue_summary": text(issue.group(1)) if issue else None,
            "fips_impact": text(fips.group(1)) if fips else None,
            "cwe": text(cwe.group(1)) if cwe else None,
        }
    return records


def acquire() -> dict:
    index_bytes = fetch(INDEX_URL)
    index_text = index_bytes.decode("utf-8", errors="replace")
    records = parse_index(index_text)
    all_references = sorted(r for r in records if _CVE.match(r))
    if not all_references:
        raise SystemExit(f"security-acquire: the index at {INDEX_URL} carried no CVE records")

    observed: list[dict] = []
    for reference in OBSERVED_REFERENCES:
        record = records.get(reference)
        if record is None:
            raise SystemExit(
                f"security-acquire: the observed selection names {reference}, which the index at "
                f"{INDEX_URL} does not carry; the source has moved and the selection must follow it"
            )
        advisory_url = record["advisory_url"]
        if not (advisory_url and _ADVISORY.match(advisory_url)):
            raise SystemExit(
                f"security-acquire: {reference} names no official advisory URL (got "
                f"{advisory_url!r}); the record cannot be bound to its primary source"
            )
        advisory_bytes = fetch(advisory_url)
        entry = {"reference": reference}
        entry.update(record)
        entry["published_at"] = _iso_date(record["published_raw"])
        entry["advisory_sha256"] = hashlib.sha256(advisory_bytes).hexdigest()
        entry["advisory_text"] = advisory_bytes.decode("utf-8", errors="replace")
        observed.append(entry)

    return {
        "schema": SCHEMA,
        "source": {
            "index_url": INDEX_URL,
            "index_sha256": hashlib.sha256(index_bytes).hexdigest(),
            "index_bytes": len(index_bytes),
            "fetched": FETCH_DATE,
            "retrieved_with": RETRIEVED_WITH,
            "all_reference_count": len(all_references),
            "all_references": all_references,
        },
        "observed": sorted(observed, key=lambda o: o["reference"]),
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="re-acquire and compare with the committed snapshot (requires network)")
    args = ap.parse_args(argv)

    snapshot = acquire()
    if args.check:
        if not OUT.is_file():
            raise SystemExit(f"security-acquire: {rel(OUT)} is absent")
        committed = json.loads(OUT.read_text(encoding="utf-8"))
        if committed != snapshot:
            raise SystemExit(
                f"security-acquire: the committed {rel(OUT)} is not what a fresh acquisition "
                f"produced; the source moved and the snapshot must be regenerated and committed"
            )
        print(f"[security-acquire] {rel(OUT)} matches a fresh acquisition")
        return 0

    write_json(OUT, snapshot)
    print(f"[security-acquire] {snapshot['source']['all_reference_count']} CVE record(s) on "
          f"{INDEX_URL}")
    print(f"  observed {len(snapshot['observed'])}: "
          + ", ".join(o["reference"] for o in snapshot["observed"]))
    print(f"  index sha256={snapshot['source']['index_sha256'][:16]}... "
          f"bytes={snapshot['source']['index_bytes']}")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
