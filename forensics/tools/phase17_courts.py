#!/usr/bin/env python3
"""openssl-rs — Phase 17 courts: the downstream replacement court.

Each court is a probe in `courts/phase17/` run **twice** — once against the admitted authority,
once against the candidate distribution shell — and the two transcripts are compared line by
line, keyed on `key=value`, and every difference is a residual. The method is Phases 3 through
16's, for the same reason: a probe measures what the authority actually does, and the
comparison is between two *executions* of the same program, so the expectation cannot drift.

`RT-CLI-BODIES`, and what it compares
-------------------------------------
17.1's court. Its subject is the CLI *executable*, which cannot be linked into a C probe, so
its instrument is the shell probe `courts/phase17/rt_cli_bodies_probe.sh` (staged as the
`artifacts/phase17/probes/rt_cli_bodies_probe.{authority,candidate}` pair the FRF runtime
harness runs, exactly as 16.4's `rt-cli` pair is). It drives the landed command bodies over a
fixed argv and compares the two transcripts.

17.1a landed `apps/errstr.c` (`src/apps/errstr.rs`): the option parser's end-of-options
boundary, the `sscanf("%lx")` success and failure arms, the failure-count exit status, and
`ERR_error_string_n`'s rendering over fixed packed error codes. 17.1b adds five more bodies
against fixed fixtures -- `info` (the four build-independent selectors and its two refusal
arms), `prime` (the numeric check, the `-hex`/decimal conversion and the no-number/`-generate`
refusals), `skeyutl` (the no-selector and selector-without-`-genkey` refusals), `configutl`
(the linearized re-emit of a fixed configuration, with and without the header), `pkeyparam`
(the default/`-noout`/`-text`/`-check` arms over a fixed `DH PARAMETERS` PEM) and `nseq`
(`-toseq` over a fixed certificate and the read/dump arm over the fixed sequence). 17.1c adds
eight more: `crl2pkcs7` (the `-nocrl -certfile` PKCS7 in PEM and DER), `ciphers` (the
`-convert` name lookup), `sess_id` (the default/text/cert/noout/context arms over a fixed
session), `kdf` (PBKDF2 over fixed `-kdfopt`s in hex and binary, and the refusal arms), `mac`
(HMAC over a fixed file, hex and binary, and the refusal arms), `spkac` (print/noout/verify/
pubkey over a fixed SPKAC config), `genrsa` and `dsaparam` (the pre-randomness bitsize and
refusal arms). 17.1d adds ten more: `asn1parse` (the PEM and raw-DER readers), `ecparam`
(`-list_curves` and `-name prime256v1` parameter generation), `rsa`/`dsa`/`ec` (the
text/re-encode/check arms over fixed keys), `pkey` (`noout`/`check`/`pubout`/`pubin`),
`pkcs8` (`topk8 -nocrypt` and the read-back arm), `verify` (the fixed CA/leaf pair),
`crl` (the text/issuer/update/crlnumber/hash/fingerprint and re-encode arms) and
`rsautl` (the refusal arms). 17.1e adds ten more: `gendsa` (the missing-argument refusal), `rand`
(the zero-length and size-suffix refusals), `rehash` (the unwritable-directory refusal),
`engine` (recorded: the candidate's engine init fails), `storeutl` (the `-noout` type/`Total
found` status over fixed fixtures), `dhparam` (the `-in` text/`-noout`/`-check` arms),
`genpkey` (the no-algorithm refusal), `passwd` (the `-1`/`-5`/`-6`-`-salt` and `-table`/`-reverse`
hashes), `pkeyutl` (`-sign`/`-verify`/`-encrypt`/`-decrypt`) and `enc` (the raw-key AES-CBC
`-e`/`-d`/`-a`/`-A`/`-nopad`/`-P` arms). Each command's `-help` arm is not driven: `opt_help` is the boundary
`src/apps/opt.rs` records, so it reaches `not_landed` rather than the authority's table,
exactly as `help`/`list`/`version` do. 17.1g, the final slice, adds the ten remaining
bodies: `x509` (the text/subject/issuer/dates/fingerprint/serial/pubkey/hash/re-encode
arms over fixed certificates), `req` (the read-back text/verify/subject/re-encode arms
over a fixed CSR), `smime` and `cms` (the `-sign`/`-verify` and fixed-fixture
`-decrypt` arms, plus the operation refusals), `pkcs12` (the deterministic
`-export -nomac -keypbe NONE -certpbe NONE`), and the parser refusals of `ca`,
`s_client`, `s_server`, `s_time` and `cmp`.

The fixtures live in `courts/phase17/fixtures/` and are read by absolute `/work` path, so the
probe is self-contained under the container's mount.

**Forty-seven inputs are recorded rather than diffed**, each a surface this stratum does not own:
`errstr 0xdeadbeef` (an unknown system errno), `info -seeds`/`-cpusettings`/`-configdir`/
`-enginesdir`/`-modulesdir` (RAND seed source, CPU dispatch and the configured prefix, which
are later strata or build-specific), `prime 2 3 4`/`-hex FF` (the `BN_print` rendering),
`ciphers`/`-v`/`-stdname`/`-tls1_2` (the `EVP`-fetch/legacy-provider surface),
`sess_id -text -cert` (the `X509_print` basicConstraints rendering), `kdf nonexistent` and
`mac NOPE` (the pointer-bearing `ERR_print_errors` tail), `spkac -spkac NOPE` (the pointer
prefix on an otherwise identical config error), `genrsa -bogus`
(`opt_set_unknown_name`), `ecparam -name <invalid>` (the pointer-bearing `ERR_print_errors`
tail), `rsa`/`dsa -modulus` (the `BN_print` rendering) and the `rsautl` operation arm
(random/binary output), plus 17.1e's: the `rand` random-stream arms, the `gendsa`/`genpkey`/
`dhparam` generation arms (not landed; random or pointer-bearing), the `passwd` random-salt arm,
and the `engine` listing/`-pre` arms (the candidate's engine init fails), plus 17.1f's: the
`dgst -bogus`/`-list`/`-mac` arms, `pkcs7 -print`, `ocsp -bogus` and its responder/verification
arms, a `ts` query without `-no_nonce` and `-reply`/`-verify`, the whole `speed` benchmark (and
its `-evp`/`-hmac` pointer-bearing refusals), `fipsinstall -module`/`-config` and the `srp`
action arms, plus 17.1g's: the `x509`/`req` generation and checking arms, the
`smime`/`cms` `-encrypt` and default (`signingTime`) `-sign` arms (and their `SMIME`
output boundary), `pkcs12 -info`/ordinary `-export`, the `ca` config/index arms, the
`s_client`/`s_server`/`s_time` network arms and every `cmp` arm. They are named in
`RECORDED_DIVERGENCES` and every other arm is
driven, the convention `src/apps/errstr.rs` and Phases 13 through 16 use for a recorded
divergence.

`RT-TLS13-INTEROP`, and what it compares
----------------------------------------
17.2's court, `courts/phase17/rt_tls13_interop_probe.c`, is 17.2's differential instrument: it
stands up a client and a server `SSL_CTX` (the server's carrying the fixed `signer.pem`/`rsa-key.pem`
fixture), connects them over two pairs of memory BIOs and pumps the flight. 17.2a lands the client's
first flight -- `tls_construct_client_hello` builds a real ClientHello over the reduced plaintext
record write. 17.2b lands the server's first flight: `tls_process_client_hello` reads the
ClientHello over a reduced plaintext record read and chooses the version/cipher/group, and
`tls_construct_server_hello` writes a real ServerHello (`supported_versions` + `X25519` key_share)
through the new `extensions_srvr` framework; the reduced group list and the client
`supported_groups`/`key_share` constructors ride along, and the `BIO_C_SET_FILENAME` constant fix
makes the fixed signer fixture load. 17.2c lands the rest of the flight (the key schedule, the
client read path and the server's encrypted flight), so both sides reach `TLS_ST_OK` and exchange a
15-byte application record. The court compares the observations the flight makes deterministic:
the record and handshake headers, the legacy/session/cipher/compression shape (including the 30
offered cipher suites), the option-gated extension bodies, the certificate-load return values, the
terminal handshake states and the application-data exchange. The candidate now also sends the
`signature_algorithms`/`ec_point_formats`/`renegotiation_info` extensions, the outer `key_share`
list length, record version `0x0303` on protected records, and a verified/signed RSA-PSS
`CertificateVerify`, so only the reduced `supported_groups`/hybrid-`key_share` (observed values,
classified by `_interop_reason`) and the option-gated extension set remain recorded rather than
diffed. This court proves each build is self-consistent; the interoperability claim is the matrix
court below.

`RT-TLS13-INTEROP-MATRIX`, and what it proves
---------------------------------------------
`RT-TLS13-INTEROP` is **not** an interoperability measurement: it builds the same probe twice and
each build runs its own client and server, so it proves a self-consistent engine on each side, not
that the two implementations meet. The interoperability court is `RT-TLS13-INTEROP-MATRIX`: because
the authority and the candidate both define the libssl/libcrypto symbols, two implementations cannot
share one process, so the matrix is **cross-process**. `courts/phase17/rt_tls13_matrix_peer.c` is
compiled twice (authority and candidate) and each peer runs one role over a real socket BIO
(`BIO_new_socket`); `courts/phase17/rt_tls13_matrix_driver.c` owns a `socketpair(AF_UNIX,
SOCK_STREAM)`, forks one peer per side and runs the four cells -- `auth-auth`, `cand-auth`,
`auth-cand`, `cand-cand` (client-server) -- exchanging one fixed 15-byte application record each
way. The two cross cells are decisive. The court's verdict is `pass` only when all four cells
complete a handshake **and** exchange application data; a cross cell that still fails leaves the
court `pending` and records the failing observation and the recorded `alert`/`ERR` stop point.

`RT-CROSS-DSO-STATE`, and what it compares
------------------------------------------
17.3's court, `courts/phase17/rt_cross_dso_state_probe.c`, measures the shared-state contract the
candidate's whole-crate archives break. The admitted authority links `libssl.so.3` against one
`libcrypto.so.3` via `DT_NEEDED`, so the crate's internal globals have one instance; the candidate
links the crate archive into both DSOs, so each carries its own copy and the two views need not
agree. The probe drives the boundary in **both directions**: it raises a deterministic error
through a libssl entry point (`SSL_CTX_new(NULL)` raises the `SSL_CTX_new_ex` NULL-method arm) and
reads the queue through libcrypto's `ERR_peek_error`/`ERR_get_error` (neither of which libssl
exports, so both resolve to `libcrypto.so.3`), and it stores an `ssl_conf` command set through
libcrypto's `CONF_modules_load_file` (over the fixed `fixtures/cross_dso.cnf`) and reads it through
libssl's `SSL_CTX_config`, observing the applied protocol version. The court reports **two
verdicts**. The *measurement verdict* is `pass` when the probe ran on both sides, the libcrypto
control and the structural return values agree (`CROSS_DSO_COMPARABLE`), and the authority itself
observed the shared contract -- `_authority_contract_problems` fails the court otherwise, so a
vacuous pass is impossible. The *compatibility verdict* is `PASS` iff the candidate's two DSOs
agree with the authority on every cross-DSO read (`CROSS_DSO_STATE`), and `KNOWN_DIVERGENCE`
otherwise, with the differing observations in `compatibility_residuals`. 17.3 landed with the
whole-crate duplication, which measured `pass`/`KNOWN_DIVERGENCE`; the runtime now resolves
libcrypto's exported `ERR_get_state` and `conf_ssl_*` owners (see `src/runtime/dso_shared.rs`), so
one queue and one store serve both DSOs and the two verdicts are `pass`/`PASS`.

The downstream consumer
-----------------------
`RT-DOWNSTREAM-CONSUMER` (17.4) is no longer pending: the probe builds a real consumer against the
candidate's *install prefix* (`artifacts/phase2/install/`) with the out-of-tree link shape
(`-I .../include -L .../lib -lssl -lcrypto -rpath`), exercises an EVP digest, an X.509 PEM parse, a
libcrypto `ERR` round-trip and a TLS 1.3 handshake over memory BIOs exchanging a fixed 15-byte
application record, and compares its transcript with the authority's. Its comparable observations
must agree; the flight's on-the-wire byte counts are `DOWNSTREAM_DIVERGENCE` and are recorded with
the candidate engine's reduction named. A residual on a comparable observation is a failure. No
court remains in `PENDING_COURTS`.

`RT-DOWNSTREAM-CORPUS`, and what it validates
--------------------------------------------
17.4a's court consumes the machine-owned downstream corpus instead of running a harness. Six
unmodified downstream programs (`courts/phase17/downstream/`) are built against the candidate
shell and exercised; the driver `courts/phase17/downstream/run_all.sh` writes one measured
record per program to `courts/phase17/downstream/<program>/result.json` and aggregates them into
`forensics/atlas/downstream-corpus.json`. The court reads that corpus and fails Phase 17 unless
every program is present, every required field (including `build`, `link`, `start`, `functional`,
`concurrency`, `known_residuals` and `historical_failures`) is present, `functional` is true, the
recorded `candidate` equals the current `Cargo.toml` version (freshness), each corpus record
still equals its per-program `result.json` (no drift), and every `historical_failures` commit is
in this history. It deliberately does **not** re-run the multi-hour builds in the gate path: the
driver is how the corpus is produced, and the court validates what was recorded.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-17-SUBPHASES.md` section 4.2 is the precondition. **No
court is registered in `gen_frf_courts.py`**: that registry is the stratum's seal, and Phase 16
registered its six courts there only at the seal (16.6), exactly as section 4.2 records.

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    resolve_authority,
    run,
    write_json,
)

# The candidate identity the corpus records must match (one release knob, `Cargo.toml`).
# `gen_frf_courts.CANDIDATE_VERSION` is that same value; importing the module rather than
# re-parsing Cargo.toml keeps a single source for "the current candidate".
import gen_frf_courts  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase17" / "COURTS.json"
GENERATOR = "forensics/tools/phase17_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-17-SUBPHASES.md"
PREREQUISITES = REPO_ROOT / "forensics" / "prerequisites.json"
PROBE_DIR = REPO_ROOT / "courts" / "phase17"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
STAGED = REPO_ROOT / "artifacts" / "phase17" / "probes"
RUN_TIMEOUT_S = "60"

AUTH_PREFIX = REPO_ROOT / "forensics" / "authorities" / "prefix" / "openssl-3.6.4-production"

# The differential courts, in the order they land. `(name, probe filename)`, and the probe is
# declared in the same commit as the entry, so a runner that names a probe which does not exist
# cannot be committed.
COURTS: list[tuple[str, str]] = [
    ("RT-CLI-BODIES", "rt_cli_bodies_probe.sh"),
    ("RT-TLS13-INTEROP", "rt_tls13_interop_probe.c"),
    ("RT-TLS13-INTEROP-MATRIX", "rt_tls13_matrix_peer.c"),
    ("RT-CROSS-DSO-STATE", "rt_cross_dso_state_probe.c"),
    ("RT-DOWNSTREAM-CONSUMER", "rt_downstream_consumer_probe.c"),
    # The corpus court consumes recorded data rather than running a multi-hour build: its
    # instrument is `forensics/atlas/downstream-corpus.json`, produced by the driver
    # `courts/phase17/downstream/run_all.sh` and described by `courts/phase17/downstream/README.md`.
    ("RT-DOWNSTREAM-CORPUS", "downstream/README.md"),
]

# The machine-owned downstream corpus: one measured record per program, aggregated. The court
# below is the seal's mechanical dependency on it -- Phase 17 cannot be `complete` while a
# program's `functional` is false or its record names a stale candidate.
DOWNSTREAM_CORPUS = REPO_ROOT / "forensics" / "atlas" / "downstream-corpus.json"
DOWNSTREAM_PROGRAMS = ["curl", "git", "haproxy", "nginx", "openssh", "python"]
DOWNSTREAM_REQUIRED_FIELDS = (
    "program", "version", "source_url", "source_sha256", "candidate", "authority",
    "build", "link", "start", "functional", "concurrency", "known_residuals",
    "historical_failures",
)

# `RT-TLS13-INTEROP-MATRIX`'s driver source. It is compiled once, without a TLS library, and forks
# the two per-side peer binaries the matrix court compiles from `rt_tls13_matrix_peer.c`.
MATRIX_DRIVER = PROBE_DIR / "rt_tls13_matrix_driver.c"

# The candidate's shipped distribution shell -- the install prefix an out-of-tree package links
# against (`-I .../include -L .../lib -lssl -lcrypto`), not the crate's internal modules. The
# downstream-consumer court is the only one that compiles against this prefix rather than the
# shell root `artifacts/phase2`.
CANDIDATE_SHELL = PHASE2 / "install"

# The fixed argv `RT-CLI-BODIES` drives on both sides. Every case is build-independent and
# deterministic: the `errstr` body's own arms -- a run of six arguments (five decode, `nothex`
# fails, so the exit status is 1), the no-argument run, and a single decode, then the 17.1b
# bodies over the fixtures under `courts/phase17/fixtures/` (read by absolute `/work` path).
# The inputs that diverge are named in `RECORDED_DIVERGENCES` and not driven.
_BODIES_FIXTURES = "/work/courts/phase17/fixtures"
BODIES_ARGV: list[list[str]] = [
    ["errstr", "0x03000041", "0x0308010C", "0x0A000041", "1", "0x00000000", "nothex"],
    ["errstr"],
    ["errstr", "0x00000000"],
    ["info", "-dsoext"],
    ["info", "-dirnamesep"],
    ["info", "-listsep"],
    ["info", "-windowscontext"],
    ["info"],
    ["info", "-dsoext", "-listsep"],
    ["prime", "97"],
    ["prime", "-hex", "0xFF"],
    ["prime", "abc"],
    ["prime"],
    ["prime", "-generate"],
    ["skeyutl"],
    ["skeyutl", "-genkey"],
    ["skeyutl", "-skeymgmt", "foo"],
    ["configutl", "-config", f"{_BODIES_FIXTURES}/configutl.cnf", "-noheader"],
    ["configutl", "-config", f"{_BODIES_FIXTURES}/configutl.cnf"],
    ["pkeyparam", "-in", f"{_BODIES_FIXTURES}/dhparams.pem"],
    ["pkeyparam", "-in", f"{_BODIES_FIXTURES}/dhparams.pem", "-noout"],
    ["pkeyparam", "-in", f"{_BODIES_FIXTURES}/dhparams.pem", "-text"],
    ["pkeyparam", "-in", f"{_BODIES_FIXTURES}/dhparams.pem", "-check"],
    ["nseq", "-toseq", "-in", f"{_BODIES_FIXTURES}/certs.pem"],
    ["nseq", "-in", f"{_BODIES_FIXTURES}/seq.pem"],
    # 17.1c: crl2pkcs7 / ciphers / sess_id / kdf / mac / spkac / genrsa / dsaparam.
    ["crl2pkcs7", "-nocrl", "-certfile", f"{_BODIES_FIXTURES}/certs.pem"],
    ["ciphers", "-convert", "TLS_AES_256_GCM_SHA384"],
    ["ciphers", "-convert", "ECDHE-RSA-AES256-GCM-SHA384"],
    ["ciphers", "-convert", "NOPE"],
    ["sess_id", "-in", f"{_BODIES_FIXTURES}/session.pem"],
    ["sess_id", "-in", f"{_BODIES_FIXTURES}/session.pem", "-text"],
    ["sess_id", "-in", f"{_BODIES_FIXTURES}/session.pem", "-cert"],
    ["sess_id", "-in", f"{_BODIES_FIXTURES}/session.pem", "-noout"],
    ["sess_id", "-in", f"{_BODIES_FIXTURES}/session.pem", "-text", "-noout"],
    ["sess_id", "-in", f"{_BODIES_FIXTURES}/session.pem", "-context", "abc"],
    ["sess_id", "-in", f"{_BODIES_FIXTURES}/session.pem", "-context",
     "123456789012345678901234567890123"],
    ["kdf", "-keylen", "16", "-kdfopt", "pass:password", "-kdfopt", "salt:NaCl",
     "-kdfopt", "iter:1", "PBKDF2"],
    ["kdf", "-keylen", "0", "PBKDF2"],
    ["kdf", "-keylen", "-1", "PBKDF2"],
    ["kdf", "-keylen", "16", "-kdfopt", "pass:p", "-kdfopt", "salt:s", "-kdfopt",
     "iter:1", "-kdfopt", "digest:SHA256", "PBKDF2"],
    ["kdf", "PBKDF2"],
    ["kdf"],
    ["mac", "-macopt", "key:secret", "HMAC", "-in", f"{_BODIES_FIXTURES}/certs.pem"],
    ["mac", "-macopt", "key:secret", "-macopt", "digest:SHA1", "HMAC", "-in",
     f"{_BODIES_FIXTURES}/certs.pem"],
    ["mac", "HMAC", "-in", f"{_BODIES_FIXTURES}/certs.pem"],
    ["mac"],
    ["spkac", "-in", f"{_BODIES_FIXTURES}/spkac.cnf"],
    ["spkac", "-in", f"{_BODIES_FIXTURES}/spkac.cnf", "-noout"],
    ["spkac", "-in", f"{_BODIES_FIXTURES}/spkac.cnf", "-verify"],
    ["spkac", "-in", f"{_BODIES_FIXTURES}/spkac.cnf", "-pubkey"],
    ["spkac", "-in", f"{_BODIES_FIXTURES}/spkac.cnf", "-verify", "-pubkey"],
    ["genrsa", "abc"],
    ["genrsa", "0"],
    ["genrsa", "99999999999999999999"],
    ["dsaparam", "abc"],
    ["dsaparam", "1", "2", "3"],
    ["dsaparam", "-text", "abc"],
    # 17.1d: asn1parse / ecparam / rsa / dsa / ec / pkey / pkcs8 / verify / crl / rsautl.
    ["asn1parse", "-in", f"{_BODIES_FIXTURES}/certs.pem"],
    ["asn1parse", "-in", f"{_BODIES_FIXTURES}/certs.pem", "-noout"],
    ["asn1parse", "-in", f"{_BODIES_FIXTURES}/cert.der", "-inform", "DER"],
    ["asn1parse", "-in", f"{_BODIES_FIXTURES}/cert.der", "-inform", "DER", "-i"],
    ["ecparam", "-list_curves"],
    ["ecparam", "-name", "prime256v1", "-noout", "-text"],
    ["ecparam", "-name", "prime256v1", "-noout"],
    ["rsa", "-in", f"{_BODIES_FIXTURES}/rsa-key.pem", "-noout", "-text"],
    ["rsa", "-in", f"{_BODIES_FIXTURES}/rsa-key.pem", "-noout"],
    ["rsa", "-in", f"{_BODIES_FIXTURES}/rsa-key.pem", "-check", "-noout"],
    ["rsa", "-in", f"{_BODIES_FIXTURES}/rsa-key.pem", "-pubin", "-noout", "-text"],
    ["rsa", "-check", "-pubin"],
    ["rsa", "-in", f"{_BODIES_FIXTURES}/rsa-key.pem"],
    ["dsa", "-in", f"{_BODIES_FIXTURES}/dsa-key.pem", "-noout", "-text"],
    ["dsa", "-in", f"{_BODIES_FIXTURES}/dsa-key.pem", "-noout"],
    ["dsa", "-in", f"{_BODIES_FIXTURES}/dsa-pub.pem", "-pubin", "-noout", "-text"],
    ["dsa", "-in", f"{_BODIES_FIXTURES}/dsa-key.pem"],
    ["ec", "-in", f"{_BODIES_FIXTURES}/ec-key.pem", "-noout", "-text"],
    ["ec", "-in", f"{_BODIES_FIXTURES}/ec-key.pem", "-noout"],
    ["ec", "-in", f"{_BODIES_FIXTURES}/ec-key.pem", "-check", "-noout"],
    ["ec", "-in", f"{_BODIES_FIXTURES}/ec-pub.pem", "-pubin", "-noout", "-text"],
    ["ec", "-in", f"{_BODIES_FIXTURES}/ec-key.pem"],
    ["pkey", "-in", f"{_BODIES_FIXTURES}/rsa-key.pem", "-noout", "-text"],
    ["pkey", "-in", f"{_BODIES_FIXTURES}/rsa-key.pem", "-check", "-noout"],
    ["pkey", "-in", f"{_BODIES_FIXTURES}/rsa-key.pem", "-pubout", "-noout", "-text"],
    ["pkey", "-in", f"{_BODIES_FIXTURES}/rsa-pub.pem", "-pubin", "-noout", "-text"],
    ["pkey", "-in", f"{_BODIES_FIXTURES}/rsa-key.pem"],
    ["pkcs8", "-topk8", "-nocrypt", "-in", f"{_BODIES_FIXTURES}/rsa-key.pem"],
    ["pkcs8", "-topk8", "-nocrypt", "-in", f"{_BODIES_FIXTURES}/rsa-key-trad.pem"],
    ["pkcs8", "-in", f"{_BODIES_FIXTURES}/rsa-key.pem", "-nocrypt"],
    ["verify", "-no-CApath", "-no-CAstore", "-CAfile", f"{_BODIES_FIXTURES}/ca.pem",
     f"{_BODIES_FIXTURES}/leaf.pem"],
    ["verify", "-CAfile", f"{_BODIES_FIXTURES}/ca.pem", f"{_BODIES_FIXTURES}/leaf.pem"],
    ["crl", "-in", f"{_BODIES_FIXTURES}/crl.pem", "-noout"],
    ["crl", "-in", f"{_BODIES_FIXTURES}/crl.pem", "-text", "-noout"],
    ["crl", "-in", f"{_BODIES_FIXTURES}/crl.pem", "-issuer", "-noout"],
    ["crl", "-in", f"{_BODIES_FIXTURES}/crl.pem", "-lastupdate", "-noout"],
    ["crl", "-in", f"{_BODIES_FIXTURES}/crl.pem", "-nextupdate", "-noout"],
    ["crl", "-in", f"{_BODIES_FIXTURES}/crl.pem", "-crlnumber", "-noout"],
    ["crl", "-in", f"{_BODIES_FIXTURES}/crl.pem", "-hash", "-noout"],
    ["crl", "-in", f"{_BODIES_FIXTURES}/crl.pem", "-fingerprint", "-noout"],
    ["crl", "-in", f"{_BODIES_FIXTURES}/crl.pem"],
    ["rsautl", "-sign", "-pubin"],
    ["rsautl", "-decrypt", "-certin"],
    ["rsautl", "-bogus"],
    # 17.1e: gendsa / rand / rehash / engine / storeutl / dhparam / genpkey / passwd /
    # pkeyutl / enc.
    ["gendsa"],
    ["rand"],
    ["rand", "0"],
    ["rand", "abc"],
    ["rand", "-hex", "abc"],
    ["rehash", "/nonexistent-phase17e"],
    ["rehash", "-v", "/nonexistent-phase17e"],
    ["storeutl", "-noout", "-keys", f"{_BODIES_FIXTURES}/rsa-key.pem"],
    ["storeutl", "-noout", "-certs", f"{_BODIES_FIXTURES}/certs.pem"],
    ["dhparam", "-in", f"{_BODIES_FIXTURES}/dhparams.pem", "-text", "-noout"],
    ["dhparam", "-in", f"{_BODIES_FIXTURES}/dhparams.pem", "-noout"],
    ["dhparam", "-in", f"{_BODIES_FIXTURES}/dhparams.pem", "-check"],
    ["genpkey"],
    ["passwd", "-1", "-salt", "abcdefgh", "secret"],
    ["passwd", "-5", "-salt", "abcdefgh01234567", "secret"],
    ["passwd", "-6", "-salt", "abcdefgh01234567", "secret"],
    ["passwd", "-1", "-salt", "abcdefgh", "-in", f"{_BODIES_FIXTURES}/pwfile.txt"],
    ["passwd", "-1", "-salt", "abcdefgh", "-table", "secret"],
    ["passwd", "-1", "-salt", "abcdefgh", "-table", "-reverse", "secret"],
    ["pkeyutl", "-sign", "-inkey", f"{_BODIES_FIXTURES}/rsa-key.pem", "-in",
     f"{_BODIES_FIXTURES}/small.bin"],
    ["pkeyutl", "-verify", "-pubin", "-inkey", f"{_BODIES_FIXTURES}/rsa-pub.pem",
     "-in", f"{_BODIES_FIXTURES}/small.bin", "-sigfile", f"{_BODIES_FIXTURES}/small.sig"],
    ["pkeyutl", "-encrypt", "-pubin", "-inkey", f"{_BODIES_FIXTURES}/rsa-pub.pem",
     "-in", f"{_BODIES_FIXTURES}/rsa256.bin", "-pkeyopt", "rsa_padding_mode:none"],
    ["pkeyutl", "-decrypt", "-inkey", f"{_BODIES_FIXTURES}/rsa-key.pem", "-in",
     f"{_BODIES_FIXTURES}/rsa256.ct", "-pkeyopt", "rsa_padding_mode:none"],
    ["enc", "-aes-128-cbc", "-K", "000102030405060708090a0b0c0d0e0f", "-iv",
     "000102030405060708090a0b0c0d0e0f", "-in", f"{_BODIES_FIXTURES}/small.bin"],
    ["enc", "-aes-128-cbc", "-K", "000102030405060708090a0b0c0d0e0f", "-iv",
     "000102030405060708090a0b0c0d0e0f", "-in", f"{_BODIES_FIXTURES}/small.enc", "-d"],
    ["enc", "-aes-128-cbc", "-K", "000102030405060708090a0b0c0d0e0f", "-iv",
     "000102030405060708090a0b0c0d0e0f", "-in", f"{_BODIES_FIXTURES}/small.bin", "-a"],
    ["enc", "-aes-128-cbc", "-K", "000102030405060708090a0b0c0d0e0f", "-iv",
     "000102030405060708090a0b0c0d0e0f", "-in", f"{_BODIES_FIXTURES}/small.bin", "-a", "-A"],
    ["enc", "-aes-128-cbc", "-K", "000102030405060708090a0b0c0d0e0f", "-iv",
     "000102030405060708090a0b0c0d0e0f", "-in", f"{_BODIES_FIXTURES}/small.bin", "-nopad"],
    ["enc", "-aes-128-cbc", "-K", "000102030405060708090a0b0c0d0e0f", "-iv",
     "000102030405060708090a0b0c0d0e0f", "-in", f"{_BODIES_FIXTURES}/small.bin", "-P", "-nosalt"],
    # 17.1f: dgst / pkcs7 / ocsp / ts / speed / fipsinstall / srp.
    ["dgst", "-sha256", f"{_BODIES_FIXTURES}/small.bin"],
    ["dgst", "-sha256", "-hex", f"{_BODIES_FIXTURES}/small.bin"],
    ["dgst", "-sha256", "-binary", f"{_BODIES_FIXTURES}/small.bin"],
    ["dgst", "-sha256", "-c", f"{_BODIES_FIXTURES}/small.bin"],
    ["dgst", "-sha256", "-r", f"{_BODIES_FIXTURES}/small.bin"],
    ["dgst", "-hmac", "secret", f"{_BODIES_FIXTURES}/small.bin"],
    ["dgst", "-sha256", "-hmac", "secret", f"{_BODIES_FIXTURES}/small.bin"],
    ["dgst", "-sha256", "-sign", f"{_BODIES_FIXTURES}/rsa-key.pem",
     f"{_BODIES_FIXTURES}/small.bin"],
    ["dgst", "-sha256", "-verify", f"{_BODIES_FIXTURES}/rsa-pub.pem", "-signature",
     f"{_BODIES_FIXTURES}/dgst.sig", f"{_BODIES_FIXTURES}/small.bin"],
    ["pkcs7", "-in", f"{_BODIES_FIXTURES}/p7.pem"],
    ["pkcs7", "-print_certs", "-in", f"{_BODIES_FIXTURES}/p7.pem"],
    ["pkcs7", "-print_certs", "-quiet", "-in", f"{_BODIES_FIXTURES}/p7.pem"],
    ["pkcs7", "-in", f"{_BODIES_FIXTURES}/p7.pem", "-outform", "DER"],
    ["ocsp"],
    ["ocsp", "-issuer", f"{_BODIES_FIXTURES}/ca.pem", "-cert",
     f"{_BODIES_FIXTURES}/leaf.pem", "-no_nonce", "-reqout", "/dev/stdout"],
    ["ocsp", "-issuer", f"{_BODIES_FIXTURES}/ca.pem", "-cert",
     f"{_BODIES_FIXTURES}/leaf.pem", "-no_nonce", "-req_text", "-out", "/dev/stdout"],
    ["ts"],
    ["ts", "-query", "-reply"],
    ["ts", "-bogus"],
    ["ts", "-query", "-no_nonce", "-data", f"{_BODIES_FIXTURES}/small.bin"],
    ["ts", "-query", "-no_nonce", "-data", f"{_BODIES_FIXTURES}/small.bin", "-text"],
    ["speed", "-bogus"],
    ["fipsinstall"],
    ["fipsinstall", "-verify"],
    ["srp"],
    ["srp", "-list", "-add"],
    ["srp", "-add"],
    ["srp", "-srpvfile", "x", "-config", "y"],
    # 17.1g: ca / cmp / cms / pkcs12 / req / s_client / s_server / s_time / smime / x509.
    ["x509", "-in", f"{_BODIES_FIXTURES}/ca.pem", "-noout", "-text"],
    ["x509", "-in", f"{_BODIES_FIXTURES}/ca.pem", "-noout", "-subject"],
    ["x509", "-in", f"{_BODIES_FIXTURES}/ca.pem", "-noout", "-issuer"],
    ["x509", "-in", f"{_BODIES_FIXTURES}/ca.pem", "-noout", "-dates"],
    ["x509", "-in", f"{_BODIES_FIXTURES}/ca.pem", "-noout", "-fingerprint"],
    ["x509", "-in", f"{_BODIES_FIXTURES}/ca.pem", "-noout", "-serial"],
    ["x509", "-in", f"{_BODIES_FIXTURES}/ca.pem", "-noout", "-pubkey"],
    ["x509", "-in", f"{_BODIES_FIXTURES}/ca.pem", "-noout", "-subject_hash"],
    ["x509", "-in", f"{_BODIES_FIXTURES}/ca.pem"],
    ["x509", "-in", f"{_BODIES_FIXTURES}/leaf.pem", "-noout", "-text"],
    ["req", "-in", f"{_BODIES_FIXTURES}/req.pem", "-noout", "-text"],
    ["req", "-in", f"{_BODIES_FIXTURES}/req.pem", "-noout", "-verify"],
    ["req", "-in", f"{_BODIES_FIXTURES}/req.pem", "-noout", "-subject"],
    ["req", "-in", f"{_BODIES_FIXTURES}/req.pem", "-noout"],
    ["smime", "-sign", "-noattr", "-nodetach", "-outform", "PEM", "-in",
     f"{_BODIES_FIXTURES}/smime.txt", "-signer", f"{_BODIES_FIXTURES}/signer.pem",
     "-inkey", f"{_BODIES_FIXTURES}/rsa-key.pem"],
    ["smime", "-sign", "-noattr", "-nodetach", "-outform", "DER", "-in",
     f"{_BODIES_FIXTURES}/smime.txt", "-signer", f"{_BODIES_FIXTURES}/signer.pem",
     "-inkey", f"{_BODIES_FIXTURES}/rsa-key.pem"],
    ["smime", "-verify", "-inform", "PEM", "-noverify", "-in",
     f"{_BODIES_FIXTURES}/smime-signed.pem"],
    ["smime", "-decrypt", "-inform", "PEM", "-in", f"{_BODIES_FIXTURES}/smime-enc.pem",
     "-recip", f"{_BODIES_FIXTURES}/signer.pem", "-inkey", f"{_BODIES_FIXTURES}/rsa-key.pem"],
    ["smime"],
    ["smime", "-encrypt", "-in", f"{_BODIES_FIXTURES}/smime.txt"],
    ["smime", "-decrypt"],
    ["smime", "-sign", "-in", f"{_BODIES_FIXTURES}/smime.txt", "-inkey",
     f"{_BODIES_FIXTURES}/rsa-key.pem"],
    ["smime", "-sign", "-in", f"{_BODIES_FIXTURES}/smime.txt"],
    ["cms", "-sign", "-noattr", "-nodetach", "-outform", "PEM", "-in",
     f"{_BODIES_FIXTURES}/smime.txt", "-signer", f"{_BODIES_FIXTURES}/signer.pem",
     "-inkey", f"{_BODIES_FIXTURES}/rsa-key.pem"],
    ["cms", "-sign", "-noattr", "-nodetach", "-outform", "DER", "-in",
     f"{_BODIES_FIXTURES}/smime.txt", "-signer", f"{_BODIES_FIXTURES}/signer.pem",
     "-inkey", f"{_BODIES_FIXTURES}/rsa-key.pem"],
    ["cms", "-verify", "-inform", "PEM", "-noverify", "-in",
     f"{_BODIES_FIXTURES}/cms-signed.pem"],
    ["cms"],
    ["cms", "-encrypt", "-in", f"{_BODIES_FIXTURES}/smime.txt"],
    ["cms", "-decrypt"],
    ["cms", "-sign", "-in", f"{_BODIES_FIXTURES}/smime.txt", "-inkey",
     f"{_BODIES_FIXTURES}/rsa-key.pem"],
    ["cms", "-sign", "-in", f"{_BODIES_FIXTURES}/smime.txt"],
    ["pkcs12", "-export", "-nomac", "-keypbe", "NONE", "-certpbe", "NONE",
     "-in", f"{_BODIES_FIXTURES}/signer.pem", "-inkey", f"{_BODIES_FIXTURES}/rsa-key.pem",
     "-passout", "pass:test"],
    ["ca", "-bogus"],
    ["ca", "-status"],
    ["s_client", "-bogus"],
    ["s_client", "-connect"],
    ["s_server", "-bogus"],
    ["s_server", "-accept"],
    ["s_time", "-bogus"],
    ["s_time", "-connect"],
]

# Divergences the court records rather than diffs: an output decided by a surface this stratum
# does not own. `errstr 0xdeadbeef` is the `ERR` surface's (`src/runtime/err.rs`);
# `info`'s five selectors are the RAND-seed-source (Phase 9), CPU-dispatch (Phase 19) and
# prefix-configured-directory surfaces; `prime`'s two are the `BN_print` rendering
# (`src/bn/bignum.rs`). The court drives every other arm and names these inputs instead of
# failing on them -- the same shape Phases 13 through 16 use for a recorded divergence.
RECORDED_DIVERGENCES: list[dict] = [
    {
        "argv": "errstr 0xdeadbeef",
        "authority": "error:DEADBEEF:system library::reason(1585561327)",
        "candidate": "error:DEADBEEF:system library::Unknown error 1588444911",
        "reason": (
            "`ERR_error_string_n` on an unknown system error: the authority's "
            "`openssl_strerror_r` (`crypto/o_str.c`, the POSIX `strerror_r`) refuses the "
            "out-of-range errno and falls back to `reason(r & ~flags)`, while the crate's "
            "`strerror_into` (`src/runtime/err.rs`) calls the GNU `strerror_r`, which answers "
            "`Unknown error N`. Recorded here rather than diffed; see `src/apps/errstr.rs`."
        ),
    },
    {
        "argv": "info -seeds",
        "authority": "os-specific",
        "candidate": "Undefined",
        "reason": (
            "`OPENSSL_info(OPENSSL_INFO_SEED_SOURCE)` (1007): the authority answers its "
            "libcrypto seed-source string; the candidate's RAND is a later stratum and the "
            "canonical `src/runtime/init.rs` `OPENSSL_info` answers NULL, so the body prints "
            "`Undefined`. Recorded here rather than diffed; see `src/apps/info.rs`."
        ),
    },
    {
        "argv": "info -cpusettings",
        "authority": "OPENSSL_ia32cap=0x7ed8320b078bffff:0x19405fdef1bf97ab:0x0000003010000110:0x0000000000000000:0x0000000000000000",
        "candidate": "Undefined",
        "reason": (
            "`OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS)` (1008): the authority answers its "
            "captured `OPENSSL_ia32cap=...` line; the candidate's CPU dispatch is Phase 19 and "
            "`OPENSSL_info(1008)` is NULL, so the body prints `Undefined`. Recorded here "
            "rather than diffed; see `src/apps/info.rs`."
        ),
    },
    {
        "argv": "info -configdir",
        "authority": "/work/forensics/authorities/prefix/openssl-3.6.4-production/ssl",
        "candidate": "",
        "reason": (
            "`OPENSSL_info(OPENSSL_INFO_CONFIG_DIR)` (1001): the authority answers its own "
            "configured prefix; the candidate's `crypto/defaults.c` `ossl_get_openssldir` "
            "answers its own build's (empty) `OPENSSLDIR`, so the body prints an empty line. "
            "Recorded here rather than diffed; see `src/apps/info.rs`."
        ),
    },
    {
        "argv": "info -enginesdir",
        "authority": "/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/engines-3",
        "candidate": "Undefined",
        "reason": (
            "`OPENSSL_info(OPENSSL_INFO_ENGINES_DIR)` (1002): the authority answers its "
            "configured engines directory; the candidate configured no prefix and answers "
            "NULL, so the body prints `Undefined`. Recorded here rather than diffed; see "
            "`src/apps/info.rs`."
        ),
    },
    {
        "argv": "info -modulesdir",
        "authority": "/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/ossl-modules",
        "candidate": "Undefined",
        "reason": (
            "`OPENSSL_info(OPENSSL_INFO_MODULES_DIR)` (1003): the authority answers its "
            "configured module directory; the candidate configured no prefix and answers "
            "NULL, so the body prints `Undefined`. Recorded here rather than diffed; see "
            "`src/apps/info.rs`."
        ),
    },
    {
        "argv": "prime 2 3 4",
        "authority": "2 (2) is prime|3 (3) is prime|4 (4) is not prime|",
        "candidate": "02 (2) is prime|03 (3) is prime|04 (4) is not prime|",
        "reason": (
            "`BN_print` rendering: the authority (`crypto/bn/bn_print.c`) strips leading "
            "nibbles and writes uppercase; the candidate (`src/bn/bignum.rs:1655`) writes "
            "lowercase and pads to whole bytes. Recorded here rather than diffed; the "
            "`prime 97` case avoids both differences. See `src/apps/prime.rs`."
        ),
    },
    {
        "argv": "prime -hex FF",
        "authority": "FF (FF) is not prime|",
        "candidate": "ff (FF) is not prime|",
        "reason": (
            "`BN_print` case: the authority writes uppercase, the candidate lowercase "
            "(`src/bn/bignum.rs:1655`). Recorded here rather than diffed; see "
            "`src/apps/prime.rs`."
        ),
    },
    {
        "argv": "ciphers",
        "authority": "<the default TLS cipher list, TLS_AES_256_GCM_SHA384:...:PSK-AES128-CBC-SHA>",
        "candidate": "",
        "reason": (
            "`ciphers`' default-list arms build a TLS context and walk "
            "`SSL_get_ciphers`. The candidate's default-list construction raises "
            "`inner_evp_generic_fetch:unsupported` for the legacy ciphers (RC4, RC2, "
            "IDEA, SEED, the GOST family), so `SSL_new` fails: exit 1, empty stdout, "
            "and those `ERR_print_errors` lines, where the authority serves the full "
            "list. The divergence is the `EVP`-fetch/legacy-provider surface's, not "
            "the body's. Recorded here rather than diffed; see `src/apps/ciphers.rs`."
        ),
    },
    {
        "argv": "ciphers -v",
        "authority": "<the default TLS cipher list, verbose>",
        "candidate": "",
        "reason": (
            "As `ciphers`: the verbose list diverges at the same default-list "
            "construction. Recorded here rather than diffed; see `src/apps/ciphers.rs`."
        ),
    },
    {
        "argv": "ciphers -stdname",
        "authority": "<the default TLS cipher list, with standard names>",
        "candidate": "",
        "reason": (
            "As `ciphers`: the standard-name list diverges at the same default-list "
            "construction. Recorded here rather than diffed; see `src/apps/ciphers.rs`."
        ),
    },
    {
        "argv": "ciphers -tls1_2",
        "authority": "<the TLS 1.2 default cipher list>",
        "candidate": "",
        "reason": (
            "As `ciphers`: pinning the protocol bound still builds the default list, "
            "so it diverges the same way. Recorded here rather than diffed; see "
            "`src/apps/ciphers.rs`."
        ),
    },
    {
        "argv": "sess_id -in <session.pem> -text -cert",
        "authority": "...|                CA:FALSE|",
        "candidate": "...|                CA:TRUE|",
        "reason": (
            "`X509_print`'s basicConstraints rendering: the authority prints "
            "`CA:FALSE` for the fixture peer certificate and the crate prints "
            "`CA:TRUE`. That is the `X509_print` extension surface's divergence, not "
            "the body's. `sess_id -cert` and `-outform DER -cert` are byte-identical "
            "and are driven. Recorded here rather than diffed; see `src/apps/sess_id.rs`."
        ),
    },
    {
        "argv": "kdf nonexistent",
        "authority": "Invalid KDF name nonexistent|kdf: Use -help for summary.|<ptr>:error:...unsupported...(nonexistent : 0)|",
        "candidate": "Invalid KDF name nonexistent|kdf: Use -help for summary.|",
        "reason": (
            "An unknown KDF name: the authority's `EVP_KDF_fetch` raises "
            "`inner_evp_generic_fetch:unsupported` and the `err:`-label "
            "`ERR_print_errors` emits that pointer-bearing line; the crate's fetch "
            "returns NULL without raising, so the candidate's queue is empty. The "
            "line begins with a per-run pointer in any case. Recorded here rather "
            "than diffed; see `src/apps/kdf.rs`."
        ),
    },
    {
        "argv": "mac NOPE",
        "authority": "Invalid MAC name NOPE|mac: Use -help for summary.|<ptr>:error:...unsupported...(NOPE : 0)|",
        "candidate": "Invalid MAC name NOPE|mac: Use -help for summary.|",
        "reason": (
            "An unknown MAC name: as `kdf nonexistent`, the authority's "
            "`EVP_MAC_fetch` raises the pointer-bearing `unsupported` line and the "
            "crate's fetch does not. Recorded here rather than diffed; see "
            "`src/apps/mac.rs`."
        ),
    },
    {
        "argv": "spkac -in <spkac.cnf> -spkac NOPE",
        "authority": "Can't find SPKAC called \"NOPE\"|<ptr>:error:0700006C:configuration file routines:NCONF_get_string:no value:...group=default name=NOPE|",
        "candidate": "Can't find SPKAC called \"NOPE\"|<ptr>:error:0700006C:configuration file routines:NCONF_get_string:no value:...group=default name=NOPE|",
        "reason": (
            "A missing SPKAC name: both sides print the same message and raise the "
            "same `NCONF_get_string:no value` error, but the rendered error line "
            "begins with a per-run pointer and cannot be diffed. Recorded here "
            "rather than diffed; see `src/apps/spkac.rs`."
        ),
    },
    {
        "argv": "genrsa -bogus",
        "authority": "genrsa: Unknown option or cipher: bogus|<ptr>:error:...unsupported...(bogus : 0)|",
        "candidate": "genrsa: Unknown option: -bogus|genrsa: Use -help for summary.|",
        "reason": (
            "`opt_set_unknown_name('cipher')` (`apps/genrsa.c:103`) makes an "
            "otherwise-unknown option a cipher name; the authority answers "
            "`Unknown option or cipher: bogus` and then the pointer-bearing fetch "
            "error. The crate's parser has no unknown-name mode, so it answers its "
            "`Unknown option: -bogus` refusal. Recorded here rather than diffed; see "
            "`src/apps/genrsa.rs`."
        ),
    },
    {
        "argv": "ecparam -name <invalid curve>",
        "authority": "unable to generate key|<ptr>:error:0800008D:elliptic curve routines:group_new_from_name:invalid curve:...ec_lib.c:1495:",
        "candidate": "unable to generate key",
        "reason": (
            "An unknown `-name`: both sides print `unable to generate key` and exit 1, "
            "but the authority's `EVP_PKEY_CTX_new_from_name`/keygen path leaves a "
            "`group_new_from_name:invalid curve` error in the queue, and the "
            "`ERR_print_errors` line begins with a per-run pointer. That tail is the "
            "`ERR` surface's. Recorded here rather than diffed; see `src/apps/ecparam.rs`."
        ),
    },
    {
        "argv": "rsa -in <rsa-key.pem> -modulus -noout",
        "authority": "Modulus=AF1F…E9B",
        "candidate": "Modulus=af1f…e9b",
        "reason": (
            "`BN_print` rendering: as `prime 2 3 4`, the authority strips leading nibbles "
            "and writes uppercase, the crate pads to whole bytes and writes lowercase "
            "(`src/bn/bignum.rs`). Recorded here rather than diffed; see "
            "`src/apps/rsa.rs`. The same divergence applies to `dsa -modulus`."
        ),
    },
    {
        "argv": "rsautl <operation>",
        "authority": "<the raw RSA result, or a PKCS#1 v1.5/OAEP ciphertext>",
        "candidate": "<not driven>",
        "reason": (
            "`rsautl`'s operation arm reads the input, runs "
            "`EVP_PKEY_verify_recover`/`_sign`/`_encrypt`/`_decrypt` and writes raw "
            "bytes; the PKCS#1 v1.5 and OAEP paddings draw randomness and the raw arms "
            "are binary. The refusal arms are driven instead. Recorded here rather than "
            "diffed; see `src/apps/rsautl.rs`."
        ),
    },
    {
        "argv": "rand 1K",
        "authority": "<1024 fresh DRBG bytes>",
        "candidate": "<1024 fresh DRBG bytes>",
        "reason": (
            "The random stream itself: both sides write a fresh DRBG output, so the "
            "bytes are independent and cannot be diffed. The zero-length and "
            "suffix-refusal arms (`rand`, `rand 0`, `rand abc`, `rand -hex abc`) are "
            "driven. Recorded here rather than diffed; see `src/apps/rand.rs`."
        ),
    },
    {
        "argv": "rand -hex 8",
        "authority": "<16 hex chars from fresh DRBG bytes>",
        "candidate": "<16 hex chars from fresh DRBG bytes>",
        "reason": (
            "As `rand 1K`: the `-hex` stream is a fresh DRBG output. Recorded here "
            "rather than diffed; see `src/apps/rand.rs`."
        ),
    },
    {
        "argv": "gendsa <missing-file>",
        "authority": "Could not open file or uri for loading key parameters of DSA parameters from ...|<ptr>:error:...",
        "candidate": "openssl-rs: command 'gendsa' is a Phase 16 boundary: its apps/gendsa.c body is not landed.",
        "reason": (
            "Key generation is not landed (the generated key is random besides); "
            "the parameter-load failure carries the pointer-bearing "
            "`ERR_print_errors` tail. The missing-argument refusal (`gendsa`) is "
            "driven. Recorded here rather than diffed; see `src/apps/gendsa.rs`."
        ),
    },
    {
        "argv": "genpkey -algorithm NOPE",
        "authority": "Error initializing NOPE context|<ptr>:error:...unsupported...(NOPE : 0)",
        "candidate": "<not landed>",
        "reason": (
            "Key generation is not landed; the unknown-algorithm arm carries the "
            "pointer-bearing `ERR_print_errors` tail. The no-algorithm refusal "
            "(`genpkey`) is driven. Recorded here rather than diffed; see "
            "`src/apps/genpkey.rs`."
        ),
    },
    {
        "argv": "passwd <password> (no -salt)",
        "authority": "$1$<random salt>$<hash>",
        "candidate": "$1$<random salt>$<hash>",
        "reason": (
            "With no `-salt` the salt is drawn through `RAND_bytes`, so the hash is "
            "fresh; the fixed-salt arms are driven. Recorded here rather than "
            "diffed; see `src/apps/passwd.rs`."
        ),
    },
    {
        "argv": "engine -pre foo",
        "authority": "(rdrand) Intel RDRAND engine|[Failure]: foo|<ptr>:error:13000089:engine routines:ENGINE_ctrl_cmd_string:invalid cmd name:...",
        "candidate": "(rdrand) Intel RDRAND engine|[Failure]: foo|<ptr>:error:...",
        "reason": (
            "The failing `-pre` control command prints a pointer-bearing "
            "`ERR_print_errors` tail on both sides. This arm is recorded with the "
            "engine listing: the candidate's engine init fails first (see the next "
            "entry), so the whole `engine` surface is recorded rather than diffed. "
            "See `src/apps/engine.rs`."
        ),
    },
    {
        "argv": "engine / engine -c / engine -t / engine -post foo",
        "authority": "(rdrand) Intel RDRAND engine| [RAND]|...|     [ available ]|(dynamic) ...|     [ unavailable ]|",
        "candidate": "",
        "reason": (
            "The candidate's `ENGINE_load_builtin_engines` calls "
            "`OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN)`, which the crate's "
            "`crypto/init.c` arm still refuses (the engine bits `eng_openssl.c`/"
            "`eng_rdrand.c` are unlanded, as `docs/PHASE-16-CLI-SEAL.md` records), so "
            "`engine` exits with `OPENSSL_init_crypto:init fail` on stderr and an empty "
            "listing where the authority prints the two built-in engines. The body is "
            "landed and its parse/listing/`-c`/`-t`/`-pre`/`-post` arms are transcribed; "
            "only this init-fail surface is the engine stratum's. Recorded here rather "
            "than diffed; see `src/apps/engine.rs`."
        ),
    },
    {
        "argv": "storeutl <missing-file>",
        "authority": "Couldn't open file or uri ...|<ptr>:error:80000002:system library:file_open:No such file or directory:...",
        "candidate": "Couldn't open file or uri ...|<ptr>:error:...",
        "reason": (
            "A failed open leaves a pointer-bearing `ERR_print_errors` tail; the "
            "`-noout -keys`/`-noout -certs` status arms over the fixed fixtures are "
            "driven. Recorded here rather than diffed; see `src/apps/storeutl.rs`."
        ),
    },
    {
        "argv": "dhparam <numbits>",
        "authority": "Generating DH parameters, ...|<the generated parameters>",
        "candidate": "<not landed>",
        "reason": (
            "Parameter generation is not landed and the generated safe prime is "
            "random; the `-in <dhparams.pem>` text/`-noout`/`-check` arms are "
            "driven. Recorded here rather than diffed; see `src/apps/dhparam.rs`."
        ),
    },
    {
        "argv": "dgst -bogus <file>",
        "authority": "dgst: Unknown option or message digest: bogus|dgst: Use -help for summary.|<ptr>:error:0308010C:...inner_evp_generic_fetch:unsupported...(bogus : 0)",
        "candidate": "dgst: Unknown option or message digest: bogus|dgst: Use -help for summary.|",
        "reason": (
            "The `-bogus` sentinel arm: both sides print the same refusal, but the "
            "authority's `opt_md_silent` (`apps/lib/opt.c:470-489`) leaves "
            "`inner_evp_generic_fetch:unsupported` in the queue and `dgst_main`'s "
            "`end:` label calls `ERR_print_errors`, so its stderr carries a "
            "pointer-bearing tail the candidate's empty queue does not. The "
            "`-sha256` fetch resolves, so every digest arm is diffed. Recorded here "
            "rather than diffed; see `src/apps/dgst.rs`."
        ),
    },
    {
        "argv": "dgst -list",
        "authority": "Supported digests:|<the fetched digest names>|",
        "candidate": "<not landed>",
        "reason": (
            "`show_digests` (`apps/dgst.c:521-549`) walks `OBJ_NAME_do_all_sorted` "
            "and fetches each name through `EVP_MD_fetch`, the fetch/legacy-provider "
            "surface `ciphers` records. The digest/HMAC/sign arms are driven. "
            "Recorded here rather than diffed; see `src/apps/dgst.rs`."
        ),
    },
    {
        "argv": "dgst -mac <name>",
        "authority": "<the MAC value over the named MAC>",
        "candidate": "<not landed>",
        "reason": (
            "`-mac` builds a MAC through `init_gen_str`/`app_keygen` "
            "(`apps/dgst.c:327-349`), whose EVP-`MAC` generation path is other "
            "strata's. The `-hmac` arm, which uses the raw HMAC key, is driven. "
            "Recorded here rather than diffed; see `src/apps/dgst.rs`."
        ),
    },
    {
        "argv": "pkcs7 -print <p7>",
        "authority": "PKCS7:|  type: pkcs7-signedData|...|          issuer: C=AU, ST=QLD, CN=SSLeay rsa test cert|...|          key: X509_PUBKEY:",
        "candidate": "PKCS7:|  type: pkcs7-signedData|...|          issuer:           validity:|...|          key: X509_PUBKEY_INTERNAL:",
        "reason": (
            "`PKCS7_print_ctx` walks `ASN1_item_print` into the certificate's own "
            "printer, so the issuer/subject name rendering and the public-key "
            "type line are the `X509_print`/`X509_PUBKEY` surface's (the same "
            "divergence `sess_id -text -cert` records). The `-print_certs` and "
            "re-encode arms avoid it and are driven. Recorded here rather than "
            "diffed; see `src/apps/pkcs7.rs`."
        ),
    },
    {
        "argv": "ocsp -bogus",
        "authority": "ocsp: Unknown option or message digest: bogus|ocsp: Use -help for summary.|<ptr>:error:0308010C:...inner_evp_generic_fetch:unsupported...(bogus : 0)",
        "candidate": "ocsp: Unknown option or message digest: bogus|ocsp: Use -help for summary.|",
        "reason": (
            "As `dgst -bogus`: the authority's `opt_md` leaves the pointer-bearing "
            "`unsupported` fetch error and `ocsp_main`'s `end:` label prints it. The "
            "no-work refusal and the fixed-CA/leaf request arms are driven. "
            "Recorded here rather than diffed; see `src/apps/ocsp.rs`."
        ),
    },
    {
        "argv": "ocsp <responder/verification arms>",
        "authority": "<a response, printing or verifying status>",
        "candidate": "<not landed>",
        "reason": (
            "`-index`/`-CA` (`load_index`), `-port`/`-url`/`-host` (a live server "
            "or `OSSL_HTTP`), `-respin`/`-rsigner`/`-rkey`/`-CAfile` verification "
            "and `-signer`/`-signkey` request signing need a responder or a "
            "network, so they cannot be diffed deterministically. The fixed "
            "`-issuer`/`-cert` request arms are driven. Recorded here rather than "
            "diffed; see `src/apps/ocsp.rs`."
        ),
    },
    {
        "argv": "ts -query (no -no_nonce) / ts -reply / ts -verify",
        "authority": "<a query with a random nonce, or a TSA response/verification>",
        "candidate": "<not landed>",
        "reason": (
            "A query without `-no_nonce` draws a random nonce through "
            "`create_nonce`; `-reply`/`-verify` need the TSA config section, "
            "`EVP_PKEY` signing and certificate verification. The "
            "`-query -no_nonce -data <file>` arm (DER and `-text`) is driven. "
            "Recorded here rather than diffed; see `src/apps/ts.rs`."
        ),
    },
    {
        "argv": "speed / speed -evp <alg> / speed -hmac <md> / speed -bogus",
        "authority": "<a wall-clock benchmark>|<ptr>:error:...",
        "candidate": "speed: Use -help for summary.| or <not landed>",
        "reason": (
            "The benchmark is a function of the machine and is never driven; "
            "`-evp NOPE`/`-hmac NOPE` also carry the pointer-bearing fetch tail "
            "(`opt_md_silent`) that the candidate's empty queue does not. `speed "
            "-bogus`, decided before any fetch, is driven. Recorded here rather "
            "than diffed; see `src/apps/speed.rs`."
        ),
    },
    {
        "argv": "fipsinstall -module <f> / -config <f>",
        "authority": "<the module MAC and INSTALL VERIFY PASSED>",
        "candidate": "<not landed>",
        "reason": (
            "`do_mac` over the module BIO, `EVP_MAC_fetch`, the self-test provider "
            "load and the config writer are the FIPS module's and the provider "
            "surface's. The `fipsinstall`/`-verify`/`-bogus` refusals are driven. "
            "Recorded here rather than diffed; see `src/apps/fipsinstall.rs`."
        ),
    },
    {
        "argv": "srp -list / -add <user> (index file)",
        "authority": "<the listed users, or a written verifier>",
        "candidate": "<not landed>",
        "reason": (
            "The action arms load a verifier-file index through "
            "`load_index`/`index_index` and the `CA_DB` type (`apps/lib/apps.c`), "
            "which this stratum does not own. The `srp`/`-add`/`-list -add`/"
            "`-srpvfile -config` refusals are driven. Recorded here rather than "
            "diffed; see `src/apps/srp.rs`."
        ),
    },
    {
        "argv": "x509 <generation/checking arms>",
        "authority": "<a generated or re-signed certificate, or a check result>",
        "candidate": "<not landed>",
        "reason": (
            "`x509 -new`/`-x509toreq`/`-req`/`-CA`/`-set_serial`/`-days`/"
            "`-not_before`/`-not_after`/`-force_pubkey`/`-key`/`-extfile` and the "
            "trust/alias writers build or mutate a certificate; `-checkend` reads "
            "the wall clock and `-purpose`/`-modulus`/`-ocspid`/`-ext`/`-email`/"
            "`-ocsp_uri`/`-alias`/`-next_serial` reach the `X509V3`/purpose/"
            "`BN_print` surfaces. The print/re-encode arms over the fixed "
            "certificate are driven. Recorded here rather than diffed; see "
            "`src/apps/x509.rs`."
        ),
    },
    {
        "argv": "req <generation arms>",
        "authority": "<a generated request/certificate, or a key modulus>",
        "candidate": "<not landed>",
        "reason": (
            "`req -new`/`-newkey`/`-key`/`-x509`/`-CA`/`-subj`/`-addext`/"
            "`-extensions`/`-precert`/`-config` build a request or certificate and "
            "`-modulus` reaches `BN_print`. The read-back `-text`/`-verify`/"
            "`-subject`/re-encode arms over the fixed CSR are driven. Recorded here "
            "rather than diffed; see `src/apps/req.rs`."
        ),
    },
    {
        "argv": "smime -encrypt / cms -encrypt / -EncryptedData_encrypt",
        "authority": "<a fresh S/MIME or CMS envelope>",
        "candidate": "<the same operation over a fresh random key>",
        "reason": (
            "The content-encryption key is drawn at random, so the envelope bytes "
            "are independent on the two sides; the fixed `smime-enc.pem`/"
            "`cms-enc.pem` fixtures are decrypted instead. Recorded here rather "
            "than diffed; see `src/apps/smime.rs` and `src/apps/cms.rs`."
        ),
    },
    {
        "argv": "smime/-cms <S/MIME output format>",
        "authority": "<a multipart S/MIME message with a fresh boundary>",
        "candidate": "<a multipart S/MIME message with a fresh boundary>",
        "reason": (
            "`SMIME_write_PKCS7`/`SMIME_write_CMS` draw a random MIME boundary, so "
            "the `SMIME` output format is not byte-deterministic; the `PEM` and "
            "`DER` output formats are driven. Recorded here rather than diffed; "
            "see `src/apps/smime.rs` and `src/apps/cms.rs`."
        ),
    },
    {
        "argv": "pkcs12 -info / <ordinary -export>",
        "authority": "MAC: sha256, Iteration 2048|…|Shrouded Keybag: … / <a salted PKCS#12>",
        "candidate": "<not landed> / <a salted PKCS#12>",
        "reason": (
            "`-info` needs `alg_print` (the `PBES2`/`PKCS12KDF` algorithm printer) "
            "and the `PKCS12_SAFEBAG` walk; the ordinary `-export` draws a random "
            "salt/MAC. The `-export -nomac -keypbe NONE -certpbe NONE` arm over the "
            "fixed certificate/key is deterministic and is driven. Recorded here "
            "rather than diffed; see `src/apps/pkcs12.rs`."
        ),
    },
    {
        "argv": "ca <config/index/issuance arms>",
        "authority": "<the CA database output, or a pointer-bearing config error>",
        "candidate": "<not landed>",
        "reason": (
            "`ca` past the option parser reads the `ca` config section and the "
            "index database and issues/revokes certificates; its failure path "
            "carries a pointer-bearing `NCONF_get_string` `ERR_print_errors` tail. "
            "The `-bogus` and missing-value parser refusals are driven. Recorded "
            "here rather than diffed; see `src/apps/ca.rs`."
        ),
    },
    {
        "argv": "s_client / s_server / s_time <network arms>",
        "authority": "<a TLS handshake, session or a wall-clock benchmark>",
        "candidate": "<not landed>",
        "reason": (
            "The transport, handshake, session cache and application-data loop (and "
            "`s_time`'s wall-clock benchmark) need a live peer and are a function of "
            "the network and machine. The parser's unknown-option and missing-value "
            "refusals (`-bogus`, `-connect`/`-accept`) are driven. Recorded here "
            "rather than diffed; see `src/apps/s_client.rs`, `src/apps/s_server.rs` "
            "and `src/apps/s_time.rs`."
        ),
    },
    {
        "argv": "smime/-cms -sign (default attributes) and -sign -noattr <invalid>",
        "authority": "<a signature carrying a signing-time attribute>",
        "candidate": "<a signature carrying its own (later) signing-time attribute>",
        "reason": (
            "`PKCS7_sign`/`CMS_sign` include the `signingTime` signed attribute from "
            "the wall clock unless `-noattr`/`-no_signing_time` is given, so the "
            "default `-sign` bytes differ across a second boundary. The driven "
            "sign arms pass `-noattr`, which removes the only wall-clock input. "
            "Recorded here rather than diffed; see `src/apps/smime.rs` and "
            "`src/apps/cms.rs`."
        ),
    },
]

# A court the plan names and this stratum cannot run yet. Each entry names the subphase that lands
# the probe and what the court will drive, so "nothing registered" is a stated distance rather than
# a court quietly dropped. 17.4 landed `RT-DOWNSTREAM-CONSUMER`, so no pending court remains.
PENDING_COURTS: dict[str, str] = {}


def side_env(libdir: Path, modulesdir: Path) -> dict[str, str]:
    """The environment a probe runs under on one side.

    `OPENSSL_MODULES` points at that side's own `ossl-modules/`; `LD_LIBRARY_PATH` fixes the DSO
    the probe resolves against, and `OPENSSL_CONF=/dev/null` keeps the host's configuration out of
    a deterministic transcript.
    """
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(libdir)
    env["OPENSSL_MODULES"] = str(modulesdir)
    env["OPENSSL_CONF"] = "/dev/null"
    env.pop("OPENSSL_CONF_INCLUDE", None)
    return env


def run_probe(binary: Path, env: dict[str, str]) -> tuple[str, str, int | None]:
    """Run one side's probe and decode its transcript **byte-for-byte**.

    The probe's subject is the CLI executable, and several of the 17.1e bodies it drives
    (`enc`'s ciphertext, `pkeyutl`'s raw sign/decrypt output) emit arbitrary binary bytes, so the
    transcript is not guaranteed UTF-8. `phase17_courts.py` therefore captures bytes and decodes
    with Latin-1, which is a 1:1 byte-to-code-point mapping: two byte-identical transcripts decode
    to identical strings and two different ones stay different, and every decoded code point is
    JSON-serialisable so a residual can be stored.
    """
    proc = subprocess.run(
        ["timeout", RUN_TIMEOUT_S, str(binary)],
        env=env,
        capture_output=True,
        check=False,
    )
    code = proc.returncode
    out = proc.stdout.decode("latin-1")
    err = proc.stderr.decode("latin-1")
    if code == 124:
        return out, err, None
    return out, err, code


def diff(authority: str, candidate: str) -> list[dict]:
    """Line-wise comparison keyed on `key=value`, so a missing or extra line produces exactly one
    residual instead of shifting every following line."""
    def parse(text: str) -> tuple[list[str], dict[str, str]]:
        order: list[str] = []
        values: dict[str, str] = {}
        for line in text.splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key not in values:
                order.append(key)
                values[key] = value
            else:
                values[key] = f"{values[key]}|{value}"
        return order, values

    a_order, a = parse(authority)
    c_order, c = parse(candidate)
    residuals: list[dict] = []
    for key in a_order:
        if key not in c:
            residuals.append({"observation": key, "authority": a[key],
                              "candidate": None, "class": "missing"})
        elif a[key] != c[key]:
            residuals.append({"observation": key, "authority": a[key],
                              "candidate": c[key], "class": "value"})
    for key in c_order:
        if key not in a:
            residuals.append({"observation": key, "authority": None,
                              "candidate": c[key], "class": "extra"})
    return residuals


def compile_probe(src: Path, out: Path, include: Path, libdir: Path) -> tuple[bool, str]:
    """Compile one side's C probe against that side's headers and shared objects.

    The method is Phase 16's (`forensics/tools/phase16_courts.py`): the same source compiles twice,
    once against the admitted authority's prefix and once against the candidate distribution shell,
    so the comparison is between two executions of one program.
    """
    res = run([
        "clang", "-std=c11", "-Wall", "-Werror=implicit-function-declaration", "-O1",
        "-D_GNU_SOURCE",
        "-I", str(include),
        "-o", str(out), str(src),
        "-L", str(libdir), "-lssl", "-lcrypto",
        f"-Wl,-rpath,{libdir}",
    ])
    return res.ok, res.stderr.strip()


def compile_driver(src: Path, out: Path) -> tuple[bool, str]:
    """Compile the `RT-TLS13-INTEROP-MATRIX` driver, which links no TLS library.

    The driver only owns the `socketpair`, the child lifetimes and the transcript; each peer
    binary it `exec`s is the one that links exactly one implementation.
    """
    res = run([
        "clang", "-std=c11", "-Wall", "-Werror=implicit-function-declaration", "-O1",
        "-D_GNU_SOURCE",
        "-o", str(out), str(src),
    ])
    return res.ok, res.stderr.strip()


# `RT-TLS13-INTEROP`'s comparable observations: the arms 17.2 drives. Each is a deterministic
# function of the build -- a message type, a protocol version, a length, a cipher-suite count, an
# extension body that does not carry a random, a certificate-load return value, or (17.2c) the
# terminal handshake state, the retry count and the application-data exchange -- so the authority's
# own two runs agree and the candidate reproducing the flight produces the same lines. Every other
# observation the probe prints is a residual classified in `_interop_reason` and recorded rather
# than diffed.
INTEROP_COMPARABLE: list[str] = [
    "ctx.client.nonnull",
    "ctx.server.nonnull",
    "server.cert.load",
    "server.key.load",
    "server.key.check",
    "server.cert.err.count",
    "client.nonnull",
    "server.nonnull",
    "client.ciphers.count",
    "flight.0.client.ret",
    "flight.0.server.ret",
    "ch.present",
    "ch.rectype",
    "ch.recversion",
    "ch.hs_type",
    "ch.legacy_version",
    "ch.random_len",
    "ch.session_id_len",
    "ch.cipher_len",
    "ch.cipher_count",
    "ch.comp_len",
    "ch.ext_count.present",
    "ch.ext.35.len",
    "ch.ext.35.data",
    "ch.ext.22.len",
    "ch.ext.22.data",
    "ch.ext.23.len",
    "ch.ext.23.data",
    "ch.ext.45.len",
    "ch.ext.45.data",
    # 17.2c: the flight now completes on both sides, so the terminal handshake state, the two
    # rounds that carry it there, and the application-data exchange are deterministic too.
    "flight.1.client.ret",
    "flight.1.server.ret",
    "flight.2.client.ret",
    "flight.2.server.ret",
    "flights.used",
    "client.state",
    "client.want",
    "client.in_init",
    "client.finished",
    "server.state",
    "server.want",
    "server.in_init",
    "server.finished",
    "app.skipped",
    "app.write.client",
    "app.client.bytes",
    "app.read.server",
    "app.server.match",
    "app.write.server",
    "app.server.bytes",
    "app.read.client",
    "app.client.match",
    "client.err.count",
    "server.err.count",
    "probe.done",
]


def _keyed(text: str) -> dict[str, str]:
    """A transcript's `key=value` map, the same parse `diff` uses (last value wins)."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            values[k] = v
    return values


def _interop_reason(key: str) -> str:
    """The named boundary a non-comparable `RT-TLS13-INTEROP` observation sits on."""
    if key.startswith("ch.ext.10"):
        return "supported_groups is constructed from the reduced built-in default list"
    if key.startswith("ch.ext.13"):
        return "signature_algorithms is not constructed (the client sigalg list is unlanded)"
    if key.startswith("ch.ext.51"):
        return (
            "key_share: the reduced default group list drops the hybrid `X25519MLKEM768`, so the "
            "candidate sends the `X25519` share (36 bytes) where the authority sends the hybrid one "
            "(1258); the hybrid share is the key-schedule boundary"
        )
    if key.startswith("ch.ext.11"):
        return "ec_point_formats is not constructed (`use_ecc` needs the group list)"
    if key.startswith("ch.ext.65281"):
        return (
            "renegotiation_info is not constructed: its guard reads the security callback's version "
            "arm, which `ssl_lib.rs` reduces to `1`"
        )
    if key.startswith("ch.ext.43"):
        return (
            "supported_versions body: the candidate's reduced security callback admits SSL3 through "
            "TLS1.2, so the offered list is longer than the authority's"
        )
    if key in ("ch.ext.types", "ch.ext_total_len", "ch.hs_len", "ch.reclen", "ch.recbytes",
               "flight.0.client.out"):
        return (
            "the extension set is partial (renegotiation_info/ec_point_formats/signature_algorithms "
            "and the hybrid key share are unlanded), so the ClientHello is smaller than the "
            "authority's"
        )
    if key.startswith("app."):
        return "application data is not reached: the handshake does not complete"
    if key in ("flights.used", "client.state", "client.want", "client.in_init",
               "client.finished", "server.state", "server.want", "server.in_init",
               "server.finished", "flight.0.server.out") or key.startswith("flight."):
        return (
            "the flight now exchanges ClientHello and ServerHello (17.2b): the server reads the "
            "ClientHello, `tls_process_client_hello` chooses TLS1.3/cipher/group and "
            "`tls_construct_server_hello` writes a ServerHello (record type 22, message type 2, "
            "supported_versions + X25519 key_share); it stops before EncryptedExtensions because "
            "the key schedule (`tls13_enc.c`) and the certificate flight are unlanded, and the "
            "client's read path cannot consume the ServerHello"
        )
    return "recorded rather than diffed"


def interop_court(name: str, src: Path, auth, work: Path) -> dict:
    """`RT-TLS13-INTEROP`: the TLS 1.3 client/server flight, differentially.

    17.2c drives the flight to completion: the client builds a real `ClientHello`, the server
    reads it and writes a real `ServerHello`, the reduced key schedule derives the handshake and
    application traffic keys from the X25519 shared secret, the server's encrypted flight
    (`EncryptedExtensions`/`Certificate`/`CertificateVerify`/`Finished`) and the client's read
    path carry both sides to `TLS_ST_OK`, and one application-data record is exchanged each way.
    The court compares every observation that flight makes deterministic: the record and handshake
    headers, the legacy/session/cipher/compression shape, the option-gated extension bodies, the
    certificate-load return values, the terminal handshake states and the application-data
    exchange. A residual on a comparable observation is a failure. The observations the flight
    does not make comparable -- the missing extensions, the hybrid key share and the
    CertificateVerify verification -- are classified by `_interop_reason` and recorded.
    """
    auth_lib = auth.libdir
    auth_inc = auth.prefix / "include"
    auth_bin = work / f"{src.stem}.authority"
    cand_bin = work / f"{src.stem}.candidate"

    ok, err = compile_probe(src, auth_bin, auth_inc, auth_lib)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-authority",
                "detail": err.splitlines()[:12]}
    ok, err = compile_probe(src, cand_bin, PHASE2 / "include", PHASE2)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-candidate",
                "detail": err.splitlines()[:12]}

    a_out, a_err, a_code = run_probe(
        auth_bin, side_env(auth_lib, auth_lib / "ossl-modules"))
    c_out, c_err, c_code = run_probe(
        cand_bin, side_env(PHASE2, PHASE2 / "install" / "lib" / "ossl-modules"))

    if not a_out.strip():
        return {"court": name, "verdict": "fail", "stage": "authority-run",
                "detail": {"exit_code": a_code, "stderr": a_err.splitlines()[:12]}}

    residuals = diff(a_out, c_out)
    comparable = set(INTEROP_COMPARABLE)
    driven = [r for r in residuals if r["observation"] in comparable]
    recorded = [r for r in residuals if r["observation"] not in comparable]
    for r in recorded:
        r["reason"] = _interop_reason(r["observation"])

    a_vals = _keyed(a_out)
    c_vals = _keyed(c_out)
    a_obs = len([l for l in a_out.splitlines() if "=" in l])
    c_obs = len([l for l in c_out.splitlines() if "=" in l])
    crashed = a_code is None or a_code < 0 or c_code is None or c_code < 0
    comparable_present = sum(
        1 for k in INTEROP_COMPARABLE if a_vals.get(k) == c_vals.get(k)
    )

    # The plan (`docs/PHASE-17-SUBPHASES.md` section 3.2): a handshake that stops at the extension
    # or key-schedule boundary is **named pending rather than counted as passing**. The court is
    # registered and drives the arms that work, but it closes only once *both* sides report a
    # finished handshake; until then its verdict is `pending` and the `tls13-interop` contract unit
    # stays open. A residual on a comparable observation is a failure either way.
    finished = (
        a_vals.get("client.finished") == "1" and a_vals.get("server.finished") == "1"
        and c_vals.get("client.finished") == "1" and c_vals.get("server.finished") == "1"
    )
    if driven:
        verdict = "fail"
    elif finished:
        verdict = "pass"
    else:
        verdict = "pending"

    staged = {}
    STAGED.mkdir(parents=True, exist_ok=True)
    for side, srcbin in (("authority", auth_bin), ("candidate", cand_bin)):
        dst = STAGED / f"{src.stem}.{side}"
        if srcbin.is_file():
            shutil.copyfile(srcbin, dst)
            dst.chmod(0o755)
            staged[side] = rel(dst)

    return {
        "court": name,
        "probe": rel(src),
        "authority_exit_code": a_code,
        "candidate_exit_code": c_code,
        "crashed": crashed,
        "comparable_keys": INTEROP_COMPARABLE,
        "authority_observations": a_obs,
        "candidate_observations": c_obs,
        "comparable_observations": comparable_present,
        "residual_count": len(driven),
        "residuals": driven,
        "recorded_divergences": recorded,
        "recorded_count": len(recorded),
        "flight_finished": finished,
        "verdict": "fail" if (driven or crashed or c_code != a_code) else verdict,
        "staged_binaries": staged,
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }


# `RT-TLS13-INTEROP-MATRIX`'s four cells, in driver order, and the observations that decide a cell.
MATRIX_CELLS: list[str] = ["auth-auth", "cand-auth", "auth-cand", "cand-cand"]


def matrix_court(name: str, peer_src: Path, driver_src: Path, auth, work: Path) -> dict:
    """`RT-TLS13-INTEROP-MATRIX`: the 2x2 cross-process interoperability matrix.

    Two implementations cannot share one process (the authority and the candidate both define the
    libssl/libcrypto symbols), so the court is cross-process: `peer_src` compiles twice, once per
    side, and `driver_src` forks one peer per side over a real `socketpair(AF_UNIX, SOCK_STREAM)`.
    The driver runs the four cells -- `auth-auth`, `cand-auth`, `auth-cand`, `cand-cand` -- and
    re-emits each peer's deterministic transcript under a `cell=<name>.<side>.<key>` prefix.

    The verdict is `pass` only when all four cells complete a handshake and exchange the fixed
    15-byte application record in both directions. A cross cell that still fails leaves the court
    `pending`; the failing cell's observations (the `alert` line and the `ERR` rendering) name the
    stop point. A failure in a same-implementation cell (`auth-auth`/`cand-cand`) or a crash is a
    `fail`, because that is a defect in one side's engine rather than a measured interop gap.
    """
    auth_lib = auth.libdir
    auth_inc = auth.prefix / "include"
    auth_peer = work / "rt_tls13_matrix_peer.authority"
    cand_peer = work / "rt_tls13_matrix_peer.candidate"
    driver = work / "rt_tls13_matrix_driver"

    ok, err = compile_probe(peer_src, auth_peer, auth_inc, auth_lib)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-authority-peer",
                "detail": err.splitlines()[:12]}
    ok, err = compile_probe(peer_src, cand_peer, PHASE2 / "include", PHASE2)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-candidate-peer",
                "detail": err.splitlines()[:12]}
    ok, err = compile_driver(driver_src, driver)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-driver",
                "detail": err.splitlines()[:12]}

    # The driver unsets `LD_LIBRARY_PATH` in each child (that would load one side's libssl into
    # the other's process) and sets each child's `OPENSSL_MODULES`; the driver itself links no TLS.
    env = dict(os.environ)
    env["OPENSSL_CONF"] = "/dev/null"
    env.pop("LD_LIBRARY_PATH", None)
    proc = subprocess.run(
        ["timeout", RUN_TIMEOUT_S, str(driver),
         str(auth_peer), str(auth_lib / "ossl-modules"),
         str(cand_peer), str(PHASE2 / "install" / "lib" / "ossl-modules"),
         str(PROBE_DIR / "fixtures")],
        env=env,
        capture_output=True,
        check=False,
    )
    code = proc.returncode
    out = proc.stdout.decode("latin-1")
    errout = proc.stderr.decode("latin-1")
    # The driver prints `cell=<name>.<side>.<key>=<value>` and a bare `cell=<name>`. Strip the
    # leading `cell=` and split the remainder at its last `=`, so the peer key (which contains no
    # `=`) becomes the map key and the value is preserved even when it does.
    vals: dict[str, str] = {}
    for line in out.splitlines():
        if line.startswith("cell="):
            rest = line[len("cell="):]
            if "=" in rest:
                path, _, value = rest.rpartition("=")
                vals[path] = value
        elif "=" in line:
            left, _, value = line.partition("=")
            vals[left] = value
    observations = len(vals)

    def peer(cell: str, side: str, key: str) -> str | None:
        return vals.get(f"{cell}.{side}.{key}")

    cells: list[dict] = []
    for cell in MATRIX_CELLS:
        complete = (
            vals.get(f"{cell}.status") == "complete"
            and peer(cell, "client", "handshake.ret") == "1"
            and peer(cell, "server", "handshake.ret") == "1"
            and peer(cell, "client", "app.match") == "1"
            and peer(cell, "server", "app.match") == "1"
        )
        cells.append({
            "cell": cell,
            "client_server": cell.split("-")[0] + " -> " + cell.split("-")[1],
            "complete": complete,
            "status": vals.get(f"{cell}.status"),
            "client_handshake": peer(cell, "client", "handshake.ret"),
            "server_handshake": peer(cell, "server", "handshake.ret"),
            "client_app_match": peer(cell, "client", "app.match"),
            "server_app_match": peer(cell, "server", "app.match"),
            "client_alert": peer(cell, "client", "alert.write"),
            "server_alert": peer(cell, "server", "alert.write"),
            "client_err": peer(cell, "client", "err.0"),
            "server_err": peer(cell, "server", "err.0"),
        })

    cross = [c for c in cells if c["cell"] in ("cand-auth", "auth-cand")]
    same = [c for c in cells if c["cell"] in ("auth-auth", "cand-cand")]
    crashed = code is None or code < 0 or vals.get("driver.done") != "1"
    if crashed or any(not c["complete"] for c in same):
        verdict = "fail"
    elif all(c["complete"] for c in cells):
        verdict = "pass"
    else:
        verdict = "pending"

    STAGED.mkdir(parents=True, exist_ok=True)
    staged = {}
    for side, srcbin in (("authority", auth_peer), ("candidate", cand_peer), ("driver", driver)):
        dst = STAGED / f"rt_tls13_matrix_peer.{side}" if side != "driver" \
            else STAGED / "rt_tls13_matrix_driver"
        if srcbin.is_file():
            shutil.copyfile(srcbin, dst)
            dst.chmod(0o755)
            staged[side] = rel(dst)

    return {
        "court": name,
        "probe": rel(peer_src),
        "driver": rel(driver_src),
        "authority_exit_code": code,
        "crashed": crashed,
        "observations": observations,
        "authority_observations": observations,
        "candidate_observations": observations,
        "comparable_observations": observations,
        "cells": cells,
        "cross_cells_pass": all(c["complete"] for c in cross),
        "verdict": verdict,
        "staged_binaries": staged,
        "candidate_stderr_tail": errout.splitlines()[-3:],
    }


# `RT-CROSS-DSO-STATE`'s comparable observations: the arms the cross-DSO boundary does *not* move --
# the libcrypto control error and the structural return values. These must agree between the sides
# for the *measurement* verdict to pass; a residual here means the probe did not drive both sides
# the same way, which is a failure rather than a recorded divergence.
CROSS_DSO_COMPARABLE: list[str] = [
    "err.crypto.peek",
    "err.crypto.lib",
    "err.crypto.reason",
    "ctx.nonnull",
    "err.ssl.null_ret",
    "conf.load.ret",
    "conf.load.peek",
    "probe.done",
]

# `RT-CROSS-DSO-STATE`'s cross-DSO observations: every read the shared-state boundary drives -- the
# error raised through libssl and read through libcrypto (`err.ssl.*`), and the `ssl_conf` store
# written through libcrypto and read through libssl (`conf.ctx_config.*`, `conf.ctx.min_proto`).
# The *compatibility* verdict is `PASS` iff the candidate equals the authority on all of them, and
# `KNOWN_DIVERGENCE` otherwise. With the whole-crate duplication this was exactly the set that
# moved (an empty libcrypto queue and a refused `SSL_CTX_config`); with one shared `libcrypto.so.3`
# it is the set both sides read identically.
CROSS_DSO_STATE: list[str] = [
    "err.ssl.peek",
    "err.ssl.lib",
    "err.ssl.reason",
    "err.ssl.get",
    "err.ssl.after_get",
    "conf.ctx_config.ret",
    "conf.ctx_config.peek",
    "conf.ctx_config.lib",
    "conf.ctx_config.reason",
    "conf.ctx.min_proto",
]

# `TLS1_2_VERSION` — the protocol version the fixture's `MinProtocol = TLSv1.2` applies.
TLS1_2_VERSION = 0x0303


def _authority_contract_problems(vals: dict[str, str]) -> list[str]:
    """The observations the admitted authority must make for this court to measure the contract.

    On the authority both DSOs share one `libcrypto.so.3` via `DT_NEEDED`, so the libssl-raised
    error must appear in libcrypto's queue, and the libcrypto-loaded `CONF` must reach libssl's
    `SSL_CTX_config` and be applied. If either is absent the probe did not drive the boundary (the
    raise or the load failed) and the run is a failure rather than a pass with an empty comparison.
    """
    problems: list[str] = []
    if vals.get("err.ssl.peek") in (None, "0x0"):
        problems.append("authority's libssl-raised error was not visible through libcrypto")
    if vals.get("conf.ctx_config.ret") != "1":
        problems.append("authority's libssl did not read the libcrypto-loaded CONF section")
    if vals.get("conf.ctx.min_proto") != str(TLS1_2_VERSION):
        problems.append("authority's libssl did not apply the CONF MinProtocol")
    return problems


def cross_dso_court(name: str, src: Path, auth, work: Path) -> dict:
    """`RT-CROSS-DSO-STATE`: the cross-DSO shared-state contract, measured in both directions.

    The probe is compiled twice and run on both sides. On the authority one `libcrypto.so.3` serves
    both DSOs, so a libssl-raised error is visible through libcrypto and a libcrypto-loaded `CONF`
    section reaches libssl; `_authority_contract_problems` fails the court if the authority does
    not observe that, so the comparison cannot pass vacuously. The court returns **two verdicts**.
    `measurement_verdict` is `pass` when the authority shares and the comparable observations agree
    -- the court *measured* the contract. `compatibility_verdict` is `PASS` iff the candidate's two
    DSOs reproduce the authority on every cross-DSO read (`CROSS_DSO_STATE`), and
    `KNOWN_DIVERGENCE` otherwise, with the differing observations in `compatibility_residuals`. The
    candidate now reaches libcrypto's exported `ERR_get_state`/`conf_ssl_*` owners
    (`src/runtime/dso_shared.rs`), so one queue and one store serve both DSOs and the two verdicts
    are `pass` and `PASS`; the separation is kept so a regression reads as a compatibility
    divergence rather than disappearing behind a measurement pass.
    """
    auth_lib = auth.libdir
    auth_inc = auth.prefix / "include"
    auth_bin = work / f"{src.stem}.authority"
    cand_bin = work / f"{src.stem}.candidate"

    ok, err = compile_probe(src, auth_bin, auth_inc, auth_lib)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-authority",
                "detail": err.splitlines()[:12]}
    ok, err = compile_probe(src, cand_bin, PHASE2 / "include", PHASE2)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-candidate",
                "detail": err.splitlines()[:12]}

    a_out, a_err, a_code = run_probe(
        auth_bin, side_env(auth_lib, auth_lib / "ossl-modules"))
    c_out, c_err, c_code = run_probe(
        cand_bin, side_env(PHASE2, PHASE2 / "install" / "lib" / "ossl-modules"))

    if not a_out.strip():
        return {"court": name, "verdict": "fail", "stage": "authority-run",
                "detail": {"exit_code": a_code, "stderr": a_err.splitlines()[:12]}}

    a_vals = _keyed(a_out)
    c_vals = _keyed(c_out)
    residuals = diff(a_out, c_out)
    comparable = set(CROSS_DSO_COMPARABLE)
    state = set(CROSS_DSO_STATE)
    # A residual on a comparable observation means the probe did not drive both sides the same way;
    # that is a measurement failure, not a compatibility divergence. A residual on a cross-DSO
    # observation is exactly what the compatibility verdict reports.
    comparable_residuals = [r for r in residuals if r["observation"] in comparable]
    compatibility_residuals = [r for r in residuals if r["observation"] in state]
    other_residuals = [
        r for r in residuals if r["observation"] not in comparable and r["observation"] not in state
    ]

    contract = _authority_contract_problems(a_vals)
    crashed = a_code is None or a_code < 0 or c_code is None or c_code < 0
    # The court measured the contract iff the authority drove it, neither side crashed, the exit
    # codes agree and the comparable observations agree.
    measurement_ok = not (contract or crashed or c_code != a_code or comparable_residuals)
    # The candidate is compatible iff it reproduced the authority on every cross-DSO read.
    compatibility_ok = measurement_ok and not compatibility_residuals
    comparable_present = sum(
        1 for k in CROSS_DSO_COMPARABLE if a_vals.get(k) == c_vals.get(k)
    )
    state_present = sum(1 for k in CROSS_DSO_STATE if a_vals.get(k) == c_vals.get(k))

    staged = {}
    STAGED.mkdir(parents=True, exist_ok=True)
    for side, srcbin in (("authority", auth_bin), ("candidate", cand_bin)):
        dst = STAGED / f"{src.stem}.{side}"
        if srcbin.is_file():
            shutil.copyfile(srcbin, dst)
            dst.chmod(0o755)
            staged[side] = rel(dst)

    return {
        "court": name,
        "probe": rel(src),
        "authority_exit_code": a_code,
        "candidate_exit_code": c_code,
        "crashed": crashed,
        "comparable_keys": CROSS_DSO_COMPARABLE,
        "state_keys": CROSS_DSO_STATE,
        "authority_observations": len([l for l in a_out.splitlines() if "=" in l]),
        "candidate_observations": len([l for l in c_out.splitlines() if "=" in l]),
        "comparable_observations": comparable_present,
        "state_observations": state_present,
        # The two verdicts the reviewer asked for: what the court measured, and whether the
        # candidate's two DSOs agree as the authority's do.
        "measurement_verdict": "pass" if measurement_ok else "fail",
        "compatibility_verdict": "PASS" if compatibility_ok else "KNOWN_DIVERGENCE",
        "compatibility_residuals": compatibility_residuals,
        "residual_count": len(comparable_residuals) + len(other_residuals),
        "residuals": comparable_residuals + other_residuals,
        "recorded_divergences": compatibility_residuals,
        "recorded_count": len(compatibility_residuals),
        "authority_contract_problems": contract,
        "authority_error_shared": a_vals.get("err.ssl.peek") not in (None, "0x0"),
        "candidate_error_shared": c_vals.get("err.ssl.peek") not in (None, "0x0"),
        "authority_conf_shared": a_vals.get("conf.ctx_config.ret") == "1",
        "candidate_conf_shared": c_vals.get("conf.ctx_config.ret") == "1",
        "verdict": "pass" if measurement_ok else "fail",
        "staged_binaries": staged,
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }


# `RT-DOWNSTREAM-CONSUMER`'s comparable observations: the slice of the exported surface that must
# behave identically for a real consumer. `DOWNSTREAM_COMPARABLE` is the EVP digest, the X.509
# parse, the libcrypto `ERR` round-trip and the TLS 1.3 flight's *semantic* results -- return
# values, digest bytes, object shape, the terminal handshake states and the application-data
# exchange. `DOWNSTREAM_DIVERGENCE` is the flight's on-the-wire byte counts, which the candidate's
# reduced engine moves (it emits smaller records than the authority's full stack); each is named by
# `_downstream_reason`. A residual on a comparable observation is a failure; a residual on a
# divergence observation is the receipt section 3.4 requires.
DOWNSTREAM_COMPARABLE: list[str] = [
    # 17.4a: EVP, a SHA-256 digest over a fixed input.
    "evp.ctx.nonnull",
    "evp.digest.init",
    "evp.digest.update",
    "evp.digest.final",
    "evp.digest.len",
    "evp.digest.hex",
    # 17.4b: X.509, a PEM parse of the fixed leaf certificate.
    "x509.bio.nonnull",
    "x509.load.nonnull",
    "x509.version",
    "x509.pubkey.nonnull",
    "x509.subject.entries",
    "x509.digest.ret",
    "x509.digest.len",
    "x509.digest.hex",
    # 17.4c: ERR, a libcrypto raise/read round-trip.
    "err.user.peek",
    "err.user.lib",
    "err.user.reason",
    "err.user.text",
    "err.user.get",
    "err.user.after_get",
    # 17.4d: TLS 1.3, the handshake's structure and its terminal state.
    "tls.ctx.client.nonnull",
    "tls.ctx.server.nonnull",
    "tls.server.cert.load",
    "tls.server.key.load",
    "tls.server.key.check",
    "tls.client.nonnull",
    "tls.server.nonnull",
    "tls.ciphers.count",
    "tls.flight.0.client.ret",
    "tls.flight.0.server.ret",
    "tls.flight.1.client.ret",
    "tls.flight.1.server.ret",
    "tls.flight.2.client.ret",
    "tls.flight.2.server.ret",
    "tls.flights.used",
    "tls.client.state",
    "tls.client.want",
    "tls.client.in_init",
    "tls.client.finished",
    "tls.server.state",
    "tls.server.want",
    "tls.server.in_init",
    "tls.server.finished",
    # the fixed 15-byte application record, exchanged each way.
    "app.skipped",
    "app.write.client",
    "app.client.bytes",
    "app.read.server",
    "app.server.match",
    "app.write.server",
    "app.server.bytes",
    "app.read.client",
    "app.client.match",
    "probe.done",
]

DOWNSTREAM_DIVERGENCE: list[str] = [
    "tls.flight.0.client.out",
    "tls.flight.0.server.out",
    "tls.flight.1.client.out",
    "tls.flight.1.server.out",
    "tls.flight.2.client.out",
    "tls.flight.2.server.out",
]


def _downstream_reason(key: str) -> str:
    """The named reduction a non-comparable `RT-DOWNSTREAM-CONSUMER` observation records."""
    if key.startswith("tls.flight") and key.endswith(".server.out"):
        return (
            "the candidate's reduced TLS 1.3 engine emits a smaller server flight than the "
            "authority's full stack -- it carries the handshake to `SSL_is_init_finished` without "
            "the authority's extra records (the post-handshake `NewSessionTicket` flight is one, "
            "`tls.flight.1.server.out` being 0 where the authority writes it) -- so the server's "
            "on-the-wire byte counts differ even though the terminal state and the application "
            "data agree (docs/PHASE-17-SUBPHASES.md section 3.4)"
        )
    return (
        "the candidate's reduced TLS 1.3 engine builds a smaller ClientHello than the "
        "authority's full stack (fewer optional extensions), so the client's on-the-wire byte "
        "counts differ even though the handshake completes and the application data matches "
        "(docs/PHASE-17-SUBPHASES.md section 3.4)"
    )


def _downstream_contract_problems(vals: dict[str, str]) -> list[str]:
    """The observations the admitted authority must make for this court to measure the contract.

    The authority is the full stack, so its consumer must actually drive every slice: the digest
    must complete, the certificate must parse, the error must round-trip, and the handshake must
    finish and carry a 15-byte application record each way. If any is absent the probe did not
    drive the exported surface and the run is a failure rather than a pass with an empty
    comparison.
    """
    problems: list[str] = []
    if vals.get("evp.digest.final") != "1" or not vals.get("evp.digest.hex"):
        problems.append("authority's EVP digest did not complete")
    if vals.get("x509.load.nonnull") != "1" or vals.get("x509.digest.ret") != "1":
        problems.append("authority's X.509 PEM parse did not succeed")
    if vals.get("err.user.reason") != "100" or vals.get("err.user.after_get") != "0x0":
        problems.append("authority's ERR round-trip did not raise and drain the fixed reason")
    if vals.get("tls.client.finished") != "1" or vals.get("tls.server.finished") != "1":
        problems.append("authority's TLS 1.3 handshake did not finish")
    if (vals.get("app.write.client") != "15" or vals.get("app.read.server") != "15"
            or vals.get("app.server.match") != "1" or vals.get("app.read.client") != "15"
            or vals.get("app.client.match") != "1"):
        problems.append("authority's 15-byte application record did not round-trip both ways")
    return problems


def downstream_court(name: str, src: Path, auth, work: Path) -> dict:
    """`RT-DOWNSTREAM-CONSUMER`: a real consumer built against the shipped distribution shell.

    The probe is compiled twice and run on both sides, but the candidate side links the *install
    prefix* (`artifacts/phase2/install/`) exactly as an out-of-tree package does -- `-I .../include`,
    `-L .../lib`, `-lssl -lcrypto`, `-rpath` -- rather than the crate's internal modules. The court
    compares the two transcripts' comparable observations (the EVP digest, the X.509 parse, the ERR
    round-trip and the TLS 1.3 flight's semantic results); a residual there is a failure. The
    candidate's reduced engine moves only the flight's on-the-wire byte counts, which are recorded
    (`recorded_divergences`, each with the reduction `_downstream_reason` names) rather than
    failing the architecture (docs/PHASE-17-SUBPHASES.md section 3.4). `_downstream_contract_problems`
    fails the court if the authority does not drive every slice, so the comparison cannot pass
    vacuously. The verdict is `pass` when the consumer works -- it links the shipped surface, runs,
    and its comparable observations match the authority's -- not only when its wires happen to
    agree.
    """
    auth_lib = auth.libdir
    auth_inc = auth.prefix / "include"
    auth_bin = work / f"{src.stem}.authority"
    cand_bin = work / f"{src.stem}.candidate"

    ok, err = compile_probe(src, auth_bin, auth_inc, auth_lib)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-authority",
                "detail": err.splitlines()[:12]}
    ok, err = compile_probe(src, cand_bin, CANDIDATE_SHELL / "include",
                            CANDIDATE_SHELL / "lib")
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-candidate",
                "detail": err.splitlines()[:12]}

    a_out, a_err, a_code = run_probe(
        auth_bin, side_env(auth_lib, auth_lib / "ossl-modules"))
    c_out, c_err, c_code = run_probe(
        cand_bin, side_env(CANDIDATE_SHELL / "lib",
                           CANDIDATE_SHELL / "lib" / "ossl-modules"))

    if not a_out.strip():
        return {"court": name, "verdict": "fail", "stage": "authority-run",
                "detail": {"exit_code": a_code, "stderr": a_err.splitlines()[:12]}}

    a_vals = _keyed(a_out)
    c_vals = _keyed(c_out)
    residuals = diff(a_out, c_out)
    comparable = set(DOWNSTREAM_COMPARABLE)
    driven = [r for r in residuals if r["observation"] in comparable]
    recorded = [r for r in residuals if r["observation"] not in comparable]
    for r in recorded:
        r["reason"] = _downstream_reason(r["observation"])

    contract = _downstream_contract_problems(a_vals)
    crashed = a_code is None or a_code < 0 or c_code is None or c_code < 0
    comparable_present = sum(
        1 for k in DOWNSTREAM_COMPARABLE if a_vals.get(k) == c_vals.get(k)
    )

    staged = {}
    STAGED.mkdir(parents=True, exist_ok=True)
    for side, srcbin in (("authority", auth_bin), ("candidate", cand_bin)):
        dst = STAGED / f"{src.stem}.{side}"
        if srcbin.is_file():
            shutil.copyfile(srcbin, dst)
            dst.chmod(0o755)
            staged[side] = rel(dst)

    return {
        "court": name,
        "probe": rel(src),
        "link_prefix": rel(CANDIDATE_SHELL),
        "authority_exit_code": a_code,
        "candidate_exit_code": c_code,
        "crashed": crashed,
        "comparable_keys": DOWNSTREAM_COMPARABLE,
        "divergence_keys": DOWNSTREAM_DIVERGENCE,
        "authority_observations": len([l for l in a_out.splitlines() if "=" in l]),
        "candidate_observations": len([l for l in c_out.splitlines() if "=" in l]),
        "comparable_observations": comparable_present,
        "residual_count": len(driven),
        "residuals": driven,
        "recorded_divergences": recorded,
        "recorded_count": len(recorded),
        "authority_contract_problems": contract,
        "authority_handshake_finished": a_vals.get("tls.client.finished") == "1"
                                        and a_vals.get("tls.server.finished") == "1",
        "candidate_handshake_finished": c_vals.get("tls.client.finished") == "1"
                                        and c_vals.get("tls.server.finished") == "1",
        "verdict": (
            "fail" if (driven or contract or crashed or c_code != a_code) else "pass"
        ),
        "staged_binaries": staged,
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }


def _commit_exists(sha: str) -> bool:
    """Whether `sha` names a commit in the checked-out history.

    The `historical_failures` list is the one authored field in a record, so the court
    re-verifies every commit it names rather than trusting the prose. `git cat-file -e
    <sha>^{commit}` is the read; a fabricated or mistyped id fails the court.
    """
    if not sha:
        return False
    r = subprocess.run(
        ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )
    return r.returncode == 0


def corpus_court(name: str) -> dict:
    """`RT-DOWNSTREAM-CORPUS`: the seal's mechanical dependency on the recorded records.

    The six downstream harnesses include multi-minute builds and live TLS servers, so this
    court does **not** re-run them: it consumes `forensics/atlas/downstream-corpus.json`,
    the aggregate of `courts/phase17/downstream/<program>/result.json`, both produced by the
    driver `courts/phase17/downstream/run_all.sh`. It fails if a program is missing, a
    required field is absent, `functional` is not true, `candidate` is not the current
    `Cargo.toml` version, a corpus record has drifted from its per-program `result.json`, the
    `concurrency` shape is malformed, or a `historical_failures` commit is not in this history.
    Because `phase_state.py` blocks a stratum on any non-`pass` court in this registry, a
    broken downstream can no longer coexist with a formal Phase-17 seal.
    """
    problems: list[str] = []
    if not DOWNSTREAM_CORPUS.is_file():
        return {"court": name, "verdict": "fail", "stage": "corpus-missing",
                "detail": rel(DOWNSTREAM_CORPUS)}

    doc = json.loads(DOWNSTREAM_CORPUS.read_text(encoding="utf-8"))
    rows = doc.get("programs") or []
    records = {r.get("program"): r for r in rows}
    current = gen_frf_courts.CANDIDATE_VERSION

    for program in DOWNSTREAM_PROGRAMS:
        r = records.get(program)
        if r is None:
            problems.append(f"{program}: missing from the corpus")
            continue
        for field in DOWNSTREAM_REQUIRED_FIELDS:
            if field not in r:
                problems.append(f"{program}: missing required field {field!r}")
        per = REPO_ROOT / "courts" / "phase17" / "downstream" / program / "result.json"
        if not per.is_file():
            problems.append(f"{program}: {rel(per)} is absent")
        elif json.loads(per.read_text(encoding="utf-8")) != r:
            problems.append(f"{program}: corpus record differs from {rel(per)}")
        if (r.get("functional") or {}).get("ok") is not True:
            problems.append(
                f"{program}: functional is not true "
                f"({(r.get('functional') or {}).get('detail', '')})")
        if r.get("candidate") != current:
            problems.append(
                f"{program}: candidate {r.get('candidate')!r} != current {current!r} (stale record)")
        conc = r.get("concurrency") or {}
        if (not isinstance(conc.get("ok"), int) or not isinstance(conc.get("total"), int)
                or conc["total"] < 1 or conc["ok"] > conc["total"]):
            problems.append(f"{program}: malformed concurrency {conc!r}")
        for h in r.get("historical_failures") or []:
            if not _commit_exists(str(h.get("commit", ""))):
                problems.append(
                    f"{program}: historical_failures commit {h.get('commit')!r} is not in this history")

    residuals = sorted({x for r in records.values()
                        for x in (r.get("known_residuals") or [])})
    return {
        "court": name,
        "probe": rel(DOWNSTREAM_CORPUS),
        "programs": sorted(records),
        "candidate": current,
        "functional": {p: bool((records.get(p, {}).get("functional") or {}).get("ok"))
                       for p in DOWNSTREAM_PROGRAMS},
        "concurrency": {p: records.get(p, {}).get("concurrency") for p in DOWNSTREAM_PROGRAMS},
        "authority_observations": sum(1 for p in DOWNSTREAM_PROGRAMS if records.get(p)),
        # `atlas_common.court_observations` requires a transcript court to carry both or neither;
        # the corpus validates the authority-side and per-program candidate records in the same
        # pass, so the two counts are equal.
        "candidate_observations": sum(1 for p in DOWNSTREAM_PROGRAMS if records.get(p)),
        "recorded_divergences": residuals,
        "problems": problems,
        # `main` prints failures through `residuals`; shape each problem as one so the reason
        # is visible rather than only the verdict.
        "residuals": [{"observation": p, "authority": "", "candidate": "", "class": "corpus"}
                      for p in problems],
        "verdict": "fail" if problems else "pass",
        "stage": "corpus",
        "frf_declarable": False,
        "frf_exclusion": (
            "corpus court: consumes the recorded downstream records, stages no probe pair and "
            "diffs no authority transcript (D13)"),
    }


def render_probe(cases: list[list[str]]) -> str:
    """The shell probe `RT-CLI-BODIES` runs on each side.

    The subject is the CLI *executable*, which cannot be linked into a C probe, so the instrument
    is a shell program: it drives `$1` (this side's `openssl`) over the fixed argv below and prints
    the same `case.N.*` transcript the court venue diffs -- key=value, newline -> `|`, CR -> `^`,
    computed identically on both sides. `$2` is the side's `ossl-modules/`, so the probe is
    self-contained under the FRF runtime harness, which sets only `LD_LIBRARY_PATH` and not
    `OPENSSL_MODULES`.
    """
    body = "\n".join(" ".join(argv) for argv in cases)
    head = '''#!/bin/sh
# openssl-rs RT-CLI-BODIES probe: drive one side's `openssl` over the court's fixed command argv
# and print one `case.N.*` line per observation. `$1` is the side's `openssl`, `$2` its
# `ossl-modules/`; the fixture (`probe-list.txt`) names this probe, which is what makes it
# challengeable (docs/DECISIONS.md D13).
#
# It is a shell probe rather than a compiled C program because the subject is the CLI
# *executable*, which is not linkable. The transcript format matches the court venue's
# `cli_transcript`: key=value, newline -> `|`, CR -> `^`.
#
# The divergent inputs (`errstr 0xdeadbeef`, `info -seeds`/`-cpusettings`/`-configdir`/
# `-enginesdir`/`-modulesdir`, `prime 2 3 4`/`-hex FF`, the `ciphers` list arms,
# `sess_id ... -text -cert`, `kdf nonexistent`, `mac NOPE`, `spkac ... -spkac NOPE`,
# `genrsa -bogus`, `ecparam -name <invalid>`, `rsa`/`dsa -modulus`, the `rsautl`
# operation arm, the 17.1e `rand` random-stream arms, the `gendsa`/`genpkey`/`dhparam`
# generation arms, `passwd` without `-salt`, the `engine` listing/`-pre` arms and the
`-bogus`/`-mac`, `pkcs7 -print`, `ocsp -bogus`/responder,
# `ts` random-nonce/`-reply`/`-verify`, `speed` benchmark/`-evp`/`-hmac`,
# `fipsinstall -module` and `srp` action arms, and the 17.1g `x509`/`req` generation,
# `smime`/`cms` `-encrypt`/S/MIME-format, `pkcs12 -info`/ordinary `-export`, the
# `ca` config/index, the `s_client`/`s_server`/`s_time` network arms and every `cmp`
# arm) are deliberately absent: each renders a
# surface this stratum does not own
# (see `forensics/tools/phase17_courts.py`'s RECORDED_DIVERGENCES and the per-command
# module headers).
# headers).
set -u
BIN="${1:?usage: rt_cli_bodies_probe.sh <openssl> <ossl-modules>}"
MODULES="${2:-}"
if [ -n "$MODULES" ]; then
    OPENSSL_MODULES="$MODULES"
    export OPENSSL_MODULES
fi
i=0
while IFS= read -r argv; do
    [ -n "$argv" ] || continue
    case "$argv" in \\#*) continue ;; esac
    out=$(mktemp)
    err=$(mktemp)
    # shellcheck disable=SC2086
    "$BIN" $argv >"$out" 2>"$err"
    code=$?
    so=$(tr '\\n' '|' <"$out" | tr '\\r' '^')
    se=$(tr '\\n' '|' <"$err" | tr '\\r' '^')
    rm -f "$out" "$err"
    printf 'case.%s.argv=%s\\n' "$i" "$argv"
    printf 'case.%s.exit=%s\\n' "$i" "$code"
    printf 'case.%s.stdout=%s\\n' "$i" "$so"
    printf 'case.%s.stderr=%s\\n' "$i" "$se"
    i=$((i + 1))
done <<'ARGS'
'''
    return head + body + "\nARGS\n"


def stage_probe(cases: list[list[str]]) -> Path:
    """Write the `RT-CLI-BODIES` shell probe and the two per-side shims, and return the source.

    The shims are the staged `artifacts/phase17/probes/rt_cli_bodies_probe.{authority,candidate}`
    pair the FRF runtime harness runs: each execs the shared source with its own side's `openssl`
    and `ossl-modules/` path, so one probe source serves both sides.
    """
    source = PROBE_DIR / "rt_cli_bodies_probe.sh"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(render_probe(cases), encoding="utf-8")
    STAGED.mkdir(parents=True, exist_ok=True)
    sides = {
        "authority": (
            AUTH_PREFIX / "bin" / "openssl",
            AUTH_PREFIX / "lib" / "ossl-modules",
        ),
        "candidate": (
            PHASE2 / "openssl",
            PHASE2 / "install" / "lib" / "ossl-modules",
        ),
    }
    for side, (binary, modules) in sides.items():
        shim = STAGED / f"rt_cli_bodies_probe.{side}"
        shim.write_text(
            "#!/bin/sh\n"
            f"exec /bin/sh /work/courts/phase17/rt_cli_bodies_probe.sh {binary} {modules}\n",
            encoding="utf-8",
        )
        shim.chmod(0o755)
    return source


def bodies_court(name: str) -> dict:
    """`RT-CLI-BODIES`: the landed command bodies over fixed argv, differentially.

    The instrument is the shell probe `stage_probe` writes -- the CLI is an executable, not a
    linkable symbol -- run once per side under the same environment the FRF runtime harness uses,
    so the court venue and the FRF court share one probe rather than two transcript generators
    that could drift.
    """
    cases = [list(argv) for argv in BODIES_ARGV]
    source = stage_probe(cases)
    a_out, a_err, a_code = run_probe(
        STAGED / "rt_cli_bodies_probe.authority",
        side_env(AUTH_PREFIX / "lib", AUTH_PREFIX / "lib" / "ossl-modules"),
    )
    c_out, c_err, c_code = run_probe(
        STAGED / "rt_cli_bodies_probe.candidate",
        side_env(PHASE2, PHASE2 / "install" / "lib" / "ossl-modules"),
    )
    residuals = diff(a_out, c_out)
    return {
        "court": name,
        "probe": rel(source),
        "authority_exit_code": a_code,
        "candidate_exit_code": c_code,
        "argv_cases": len(cases),
        "authority_observations": len([l for l in a_out.splitlines() if "=" in l]),
        "candidate_observations": len([l for l in c_out.splitlines() if "=" in l]),
        "residual_count": len(residuals),
        "residuals": residuals[:24],
        "recorded_divergences": RECORDED_DIVERGENCES,
        "verdict": (
            "pass" if not residuals and a_code == c_code else "fail"
        ),
        "staged_binaries": {
            "authority": rel(STAGED / "rt_cli_bodies_probe.authority"),
            "candidate": rel(STAGED / "rt_cli_bodies_probe.candidate"),
        },
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    work = REPO_ROOT / "court" / "phase17"
    work.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    for name, filename in COURTS:
        if name == "RT-DOWNSTREAM-CORPUS":
            records.append(corpus_court(name))
            continue
        src = PROBE_DIR / filename
        if name == "RT-CLI-BODIES":
            records.append(bodies_court(name))
            continue
        if not src.is_file():
            records.append({"court": name, "verdict": "fail",
                            "stage": "probe-missing", "detail": rel(src)})
            continue
        if name == "RT-CROSS-DSO-STATE":
            records.append(cross_dso_court(name, src, auth, work))
            continue
        if name == "RT-TLS13-INTEROP-MATRIX":
            records.append(matrix_court(name, src, MATRIX_DRIVER, auth, work))
            continue
        if name == "RT-DOWNSTREAM-CONSUMER":
            records.append(downstream_court(name, src, auth, work))
            continue
        records.append(interop_court(name, src, auth, work))

    passed = sum(1 for r in records if r["verdict"] == "pass")
    pending = sum(1 for r in records if r["verdict"] == "pending")
    failed = sum(1 for r in records if r["verdict"] == "fail")
    body = {
        # `all_pass` is true only when every registered court is *closed*; a registered-but-pending
        # court (the flight that stops at the extension boundary, section 3.2) makes it false while
        # the runner's exit status stays 0, because a pending distance is the stratum's expected
        # in-progress state rather than a failure.
        "all_pass": failed == 0 and pending == 0,
        "authority": auth.id,
        "courts": records,
        "summary": {
            "total": len(records),
            "pass": passed,
            "pending": pending,
            "fail": failed,
        },
        "pending_courts": PENDING_COURTS,
        "claim": (
            "`RT-CLI-BODIES` is 17.1's court: it **runs** the authority's own built `openssl` and "
            "the candidate distribution shell's over a fixed argv, comparing the two transcripts "
            "line by line. 17.1a drives `errstr` -- the option parser's end-of-options boundary, "
            "the `sscanf(\"%lx\")` success and failure arms, the failure-count exit status and "
            "`ERR_error_string_n`'s rendering over fixed packed error codes. 17.1b adds five "
            "bodies over fixed fixtures: `info` (four build-independent selectors and two refusal "
            "arms), `prime` (the numeric check, the `-hex` refusal and the no-number/`-generate` "
            "refusals), `skeyutl` (the no-selector and selector-without-`-genkey` refusals), "
            "`configutl` (a fixed configuration's linearized re-emit, with and without the "
            "header), `pkeyparam` (the default/`-noout`/`-text`/`-check` arms over a fixed "
            "`DH PARAMETERS` PEM) and `nseq` (`-toseq` over a fixed certificate and the "
            "read/dump arm over the fixed sequence), all through the shell probe "
            "courts/phase17/rt_cli_bodies_probe.sh, the per-side staged pair the FRF runtime "
            "harness runs. 17.1c adds eight more bodies over fixed fixtures: `crl2pkcs7` (the "
            "`-nocrl -certfile` PKCS7 in PEM and DER), `ciphers` (the `-convert` name lookup), "
            "`sess_id` (the default/`-text`/`-cert`/`-noout`/`-context` arms over a fixed "
            "session), `kdf` (PBKDF2 over fixed `-kdfopt`s in hex and binary, plus the refusal "
            "arms), `mac` (HMAC over a fixed file, hex and binary, plus the refusal arms), "
            "`spkac` (the print/`-noout`/`-verify`/`-pubkey` arms over a fixed SPKAC config), "
            "`genrsa` and `dsaparam` (the pre-randomness bitsize and refusal arms). 17.1d adds "
            "ten more bodies over fixed fixtures: `asn1parse` (the generic PEM reader and the "
            "raw DER reader, with and without `-i`), `ecparam` (`-list_curves` and the "
            "`-name prime256v1` parameter generation), `rsa`/`dsa`/`ec` (the private/public "
            "text and re-encode arms, and `rsa -check -pubin`'s refusal), `pkey` (the "
            "`-noout`/`-check`/`-pubout`/`-pubin`/default arms), `pkcs8` (the `-topk8 -nocrypt` "
            "and read-back arms), `verify` (the fixed CA/leaf pair), `crl` (the "
            "text/issuer/update/crlnumber/hash/fingerprint and re-encode arms) and `rsautl` "
            "(the private-key-required and unknown-option refusals). 17.1e adds ten more bodies "
            "over fixed fixtures: `gendsa` (the missing-argument refusal), `rand` (the "
            "zero-length and size-suffix refusals), `rehash` (the unwritable-directory "
            "refusal), `storeutl` (the `-noout -keys`/`-noout -certs` type and `Total found` "
            "status), `dhparam` (the `-in` text/`-noout`/`-check` arms), `genpkey` (the "
            "no-algorithm refusal), `passwd` (the fixed-salt `-1`/`-5`/`-6` and "
            "`-table`/`-reverse` hashes), `pkeyutl` (`-sign`/`-verify`/`-encrypt`/`-decrypt` "
            "over the fixed key/input) and `enc` (the raw-key AES-CBC `-e`/`-d`/`-a`/`-A`/"
            "`-nopad`/`-P` arms); `engine`'s listing arms are recorded because the "
            "candidate's engine init fails. 17.1f adds seven more bodies over fixed "
            "fixtures: `dgst` (the digest, `-hex`/`-binary`, `-c`/`-r`, `-hmac`, "
            "`-sign` and `-verify` arms), `pkcs7` (the re-encode and `-print_certs` "
            "arms), `ocsp` (the no-work refusal and the fixed-CA/leaf `-reqout`/"
            "`-req_text` request arms), `ts` (the mode refusals and the "
            "`-query -no_nonce -data` DER/text arms), `speed` (the `-bogus` "
            "refusal), `fipsinstall` (the `-verify`/no-module refusals) and `srp` "
            "(the action-count refusals). 17.1g, the final slice, lands the last ten "
            "bodies over fixed fixtures: `x509` (the "
            "text/subject/issuer/dates/fingerprint/serial/pubkey/hash and re-encode arms), "
            "`req` (the read-back `-text`/`-verify`/`-subject`/re-encode arms over a fixed "
            "CSR), `smime` and `cms` (the `-sign -nodetach -outform PEM|DER` over a fixed "
            "content/signer/key, the `-verify -noverify` and `-decrypt` over fixed "
            "fixtures, and the operation refusals), `pkcs12` (the deterministic "
            "`-export -nomac -keypbe NONE -certpbe NONE`), and the option-parser refusals "
            "of `ca`, `s_client`, `s_server`, `s_time` and `cmp`. Each "
            "command's `-help` arm is not driven (`opt_help` is unlanded), and the many "
            "divergent inputs -- `errstr 0xdeadbeef`, `info -seeds`/`-cpusettings`/`-configdir`/ "
            "`-enginesdir`/`-modulesdir`, `prime 2 3 4`/`-hex FF`, the `ciphers` list arms, "
            "`sess_id ... -text -cert`, `kdf nonexistent`, `mac NOPE`, `spkac ... -spkac NOPE`, "
            "`genrsa -bogus`, `ecparam -name <invalid>`, `rsa`/`dsa -modulus`, the `rsautl` "
            "operation arm, the 17.1e `rand` random-stream arms, the `gendsa`/`genpkey`/`dhparam` "
            "generation arms, `passwd` without `-salt` and the `engine` listing/`-pre` arms, and "
            "the 17.1f `dgst -bogus`/`-list`/`-mac`, `pkcs7 -print`, `ocsp -bogus`/responder, "
            "`ts` nonce/`-reply`/`-verify`, `speed` benchmark/`-evp`/`-hmac`, "
            "`fipsinstall -module` and `srp` action arms -- "
            "are recorded "
            "in `recorded_divergences` rather than diffed. `RT-TLS13-INTEROP` is 17.2's: 17.2a "
            "registers it over the probe courts/phase17/rt_tls13_interop_probe.c, which connects a "
            "client and a server over memory BIOs and drives the flight. 17.2a lands "
            "tls_construct_client_hello over a reduced plaintext record write; 17.2b lands the "
            "server's first flight -- tls_process_client_hello over a reduced plaintext record read "
            "and tls_construct_server_hello plus the extensions_srvr framework and the reduced "
            "group/key-share infrastructure -- and fixes the BIO_C_SET_FILENAME constant so the "
            "fixture loads. 17.2c lands the rest of the flight: the reduced TLS1.3 key schedule "
            "(src/ssl/tls13_enc.rs -- HKDF-Extract/Expand over SHA256/SHA384, the early/handshake/"
            "master secrets, the handshake and application traffic secrets, the Finished MAC and "
            "per-record AES-GCM/ChaCha20-Poly1305 protection), the client's read path "
            "(tls_process_server_hello and the EncryptedExtensions/Certificate/CertificateVerify/"
            "Finished handlers) and the server's encrypted flight "
            "(tls_construct_encrypted_extensions/certificate/cert_verify/finished). Both sides now "
            "reach TLS_ST_OK, report SSL_is_init_finished, and exchange a 15-byte application "
            "record in each direction, so the court compares the terminal states, the two "
            "carrying rounds and the application-data exchange as well as the first-flight "
            "structure. The reduced flight now also sends the three ClientHello extensions it was "
            "missing (`signature_algorithms`, `ec_point_formats`, `renegotiation_info`) and the "
            "outer `key_share` list length the authority's parser reads, carries record version "
            "0x0303 on protected records, validates the peer's RSA-PSS CertificateVerify and signs "
            "its own with `rsa_pss_rsae_sha256`, and skips the middlebox-compatibility "
            "ChangeCipherSpec -- so the same-implementation flight and the cross-implementation "
            "matrix agree. `RT-TLS13-INTEROP-MATRIX` is 17.2's interoperability court: it compiles "
            "courts/phase17/rt_tls13_matrix_peer.c twice (authority and candidate) and runs "
            "courts/phase17/rt_tls13_matrix_driver.c, which forks one peer per side over a real "
            "AF_UNIX socketpair and drives the four cells `auth-auth`/`cand-auth`/`auth-cand`/"
            "`cand-cand`, exchanging a fixed 15-byte application record each way. The verdict is "
            "`pass` only when all four cells handshake and exchange application data; the two "
            "cross cells are the interoperability receipt. "
            "`RT-CROSS-DSO-STATE` is 17.3's: it registers the probe "
            "courts/phase17/rt_cross_dso_state_probe.c and measures the shared-state contract the "
            "candidate's whole-crate archives break, in both directions -- a libssl-raised error "
            "read through libcrypto's ERR queue, and a `CONF` command set `CONF_modules_load_file` "
            "stored through libcrypto read through libssl's `SSL_CTX_config` (over the fixed "
            "fixtures/cross_dso.cnf). It reports two verdicts: a *measurement verdict*, `pass` "
            "when the authority shares one `libcrypto.so.3` via `DT_NEEDED` and drove both reads "
            "(so the comparison cannot be vacuous), and a *compatibility verdict*, `PASS` iff the "
            "candidate's two DSOs reproduce the authority on every cross-DSO read and "
            "`KNOWN_DIVERGENCE` otherwise. 17.3 landed with the whole-crate duplication "
            "(`err.ssl.peek=0`, `conf.ctx_config.ret=0`), so the compatibility verdict began as "
            "`KNOWN_DIVERGENCE`; the runtime now resolves libcrypto's exported "
            "`ERR_get_state`/`conf_ssl_*` owners (`src/runtime/dso_shared.rs`), so one queue and "
            "one store serve both DSOs and the verdicts are `pass`/`PASS`. "
            "counts. `RT-DOWNSTREAM-CONSUMER` is 17.4's: "
            "courts/phase17/rt_downstream_consumer_probe.c is a real downstream consumer linked "
            "only against the shipped install prefix (an EVP digest, an X.509 PEM parse, a "
            "libcrypto ERR round-trip and a TLS 1.3 handshake over memory BIOs exchanging a fixed "
            "15-byte application record), and the court records the flight's on-the-wire byte "
            "counts the candidate's reduced engine moves rather than asserting wire parity "
            "(section 3.4). `RT-DOWNSTREAM-CORPUS` is 17.4a's: it consumes the machine-owned "
            "downstream corpus (forensics/atlas/downstream-corpus.json, aggregated from the six "
            "courts/phase17/downstream/<program>/result.json records the driver run_all.sh writes) "
            "and fails Phase 17 unless every program is present, every required field is present, "
            "functional is true, candidate equals the current Cargo.toml version, and each corpus "
            "record still equals its per-program result.json. No court remains pending. This "
            "stratum owns no exported symbol, so no differential probe over a symbol set is its "
            "evidence. No court is registered in forensics/tools/gen_frf_courts.py: that registry "
            "is the stratum's seal (section 4.2), as Phase 16 registered its six courts only at "
            "16.6. docs/PHASE-17-SUBPHASES.md sections 1, 3 and 4 record the measurement and the "
            "courts (docs/DECISIONS.md D530)."
        ),
    }

    inputs = [
        InputRef(name="phase-17-plan", path=PLAN),
        InputRef(name="prerequisites", path=PREREQUISITES),
        InputRef(name="probe", path=PROBE_DIR / "rt_cli_bodies_probe.sh"),
        InputRef(name="interop-probe", path=PROBE_DIR / "rt_tls13_interop_probe.c"),
        InputRef(name="interop-cert", path=PROBE_DIR / "fixtures" / "signer.pem"),
        InputRef(name="interop-key", path=PROBE_DIR / "fixtures" / "rsa-key.pem"),
        InputRef(name="matrix-peer", path=PROBE_DIR / "rt_tls13_matrix_peer.c"),
        InputRef(name="matrix-driver", path=PROBE_DIR / "rt_tls13_matrix_driver.c"),
        InputRef(name="cross-dso-probe", path=PROBE_DIR / "rt_cross_dso_state_probe.c"),
        InputRef(name="cross-dso-conf", path=PROBE_DIR / "fixtures" / "cross_dso.cnf"),
        InputRef(name="downstream-probe",
                 path=PROBE_DIR / "rt_downstream_consumer_probe.c"),
        InputRef(name="downstream-leaf", path=PROBE_DIR / "fixtures" / "leaf.pem"),
        InputRef(name="downstream-corpus", path=DOWNSTREAM_CORPUS),
        InputRef(name="downstream-readme",
                 path=REPO_ROOT / "courts" / "phase17" / "downstream" / "README.md"),
        *[InputRef(name=f"downstream-{p}-record",
                   path=REPO_ROOT / "courts" / "phase17" / "downstream" / p / "result.json")
          for p in DOWNSTREAM_PROGRAMS],
    ]
    doc = envelope(kind="phase17-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "pass":
            extra = ""
            if "measurement_verdict" in r:
                # The cross-DSO court reports two verdicts: what it measured and whether the
                # candidate's DSOs agree as the authority's do.
                extra = (f" [measurement={r['measurement_verdict']}, "
                         f"compatibility={r['compatibility_verdict']}]")
            print(f"  {r['court']:<18} pass   ({r['authority_observations']} observations, "
                  f"{len(r.get('recorded_divergences', []))} recorded divergence(s)){extra}")
        elif r["verdict"] == "pending":
            print(f"  {r['court']:<18} PENDING (registered; {r['comparable_observations']} "
                  f"comparable observation(s), full flight not finished) -- "
                  f"{r.get('recorded_count', 0)} recorded divergence(s)")
        else:
            print(f"  {r['court']:<18} FAIL   stage={r.get('stage', 'compare')}")
            for res in r.get("residuals", [])[:12]:
                print(f"      {res['observation']}: authority={res['authority']!r} "
                      f"candidate={res['candidate']!r} ({res['class']})")
    for name, needs in PENDING_COURTS.items():
        print(f"  {name:<24} PENDING (not registered) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s) "
          f"(pass={passed} pending={pending} fail={failed})")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
