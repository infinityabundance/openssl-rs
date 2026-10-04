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
`rsautl` (the refusal arms). Each command's `-help` arm is not driven: `opt_help` is the boundary
`src/apps/opt.rs` records, so it reaches `not_landed` rather than the authority's table,
exactly as `help`/`list`/`version` do.

The fixtures live in `courts/phase17/fixtures/` and are read by absolute `/work` path, so the
probe is self-contained under the container's mount.

**Twenty inputs are recorded rather than diffed**, each a surface this stratum does not own:
`errstr 0xdeadbeef` (an unknown system errno), `info -seeds`/`-cpusettings`/`-configdir`/
`-enginesdir`/`-modulesdir` (RAND seed source, CPU dispatch and the configured prefix, which
are later strata or build-specific), `prime 2 3 4`/`-hex FF` (the `BN_print` rendering),
`ciphers`/`-v`/`-stdname`/`-tls1_2` (the `EVP`-fetch/legacy-provider surface),
`sess_id -text -cert` (the `X509_print` basicConstraints rendering), `kdf nonexistent` and
`mac NOPE` (the pointer-bearing `ERR_print_errors` tail), `spkac -spkac NOPE` (the pointer
prefix on an otherwise identical config error), `genrsa -bogus`
(`opt_set_unknown_name`), `ecparam -name <invalid>` (the pointer-bearing `ERR_print_errors`
tail), `rsa`/`dsa -modulus` (the `BN_print` rendering) and the `rsautl` operation arm
(random/binary output). They are named in `RECORDED_DIVERGENCES` and every other arm is
driven, the convention `src/apps/errstr.rs` and Phases 13 through 16 use for a recorded
divergence.

The pending courts
------------------
Three of the four courts the plan names are still not runnable at 17.1 and are named in
`PENDING_COURTS` with the subphase that lands each:

  * `RT-TLS13-INTEROP` (17.2) — a real TLS 1.3 client/server flight, ClientHello through Finished
    plus an application-data exchange, over the record layer, the extension units and the key
    schedule (D530's first entrance criterion);
  * `RT-CROSS-DSO-STATE` (17.3) — an error raised through the libssl path and read through the
    libcrypto path (and the same for `CONF`), requiring one queue across the candidate's
    whole-crate archives, where the authority shares one `libcrypto.so.3` via `DT_NEEDED` (D530's
    second);
  * `RT-DOWNSTREAM-CONSUMER` (17.4) — a real downstream consumer built against the candidate
    distribution shell the way an out-of-tree package links it.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-17-SUBPHASES.md` section 4.2 is the precondition. **No
court is registered in `gen_frf_courts.py`**: that registry is the stratum's seal, and Phase 16
registered its six courts there only at the seal (16.6), exactly as section 4.2 records.

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import os
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
]

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
]

# A court the plan names and this stratum cannot run yet. Each entry names the subphase that lands
# the probe and what the court will drive, so "nothing registered" is a stated distance rather than
# a court quietly dropped.
PENDING_COURTS: dict[str, str] = {
    "RT-TLS13-INTEROP": (
        "17.2 lands the probe; it drives a real TLS 1.3 client/server flight, ClientHello through "
        "Finished plus an application-data exchange, and compares the two transcripts"
    ),
    "RT-CROSS-DSO-STATE": (
        "17.3 lands the probe; it raises an ERR through the libssl path and reads it through the "
        "libcrypto path (and the same for CONF), requiring one queue across the whole-crate DSOs"
    ),
    "RT-DOWNSTREAM-CONSUMER": (
        "17.4 lands the probe; it builds a real downstream consumer against the candidate "
        "distribution shell and compares its transcript with the authority's"
    ),
}


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
    res = run(["timeout", RUN_TIMEOUT_S, str(binary)], env=env)
    code = res.returncode
    if code == 124:
        return res.stdout, res.stderr, None
    return res.stdout, res.stderr, code


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
# `genrsa -bogus`, `ecparam -name <invalid>`, `rsa`/`dsa -modulus` and the `rsautl`
# operation arm) are deliberately absent: each renders a surface this stratum does not own
# (see `forensics/tools/phase17_courts.py`'s RECORDED_DIVERGENCES and the per-command module
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
        src = PROBE_DIR / filename
        if not src.is_file() and name != "RT-CLI-BODIES":
            records.append({"court": name, "verdict": "fail",
                            "stage": "probe-missing", "detail": rel(src)})
            continue
        records.append(bodies_court(name))

    passed = sum(1 for r in records if r["verdict"] == "pass")
    body = {
        "all_pass": passed == len(records),
        "authority": auth.id,
        "courts": records,
        "summary": {"total": len(records), "pass": passed, "fail": len(records) - passed},
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
            "(the private-key-required and unknown-option refusals). Each "
            "command's `-help` arm is not driven (`opt_help` is unlanded), and the twenty "
            "divergent inputs -- `errstr 0xdeadbeef`, `info -seeds`/`-cpusettings`/`-configdir`/ "
            "`-enginesdir`/`-modulesdir`, `prime 2 3 4`/`-hex FF`, the `ciphers` list arms, "
            "`sess_id ... -text -cert`, `kdf nonexistent`, `mac NOPE`, `spkac ... -spkac NOPE`, "
            "`genrsa -bogus`, `ecparam -name <invalid>`, `rsa`/`dsa -modulus` and the `rsautl` "
            "operation arm -- are recorded "
            "in `recorded_divergences` rather than diffed. `RT-TLS13-INTEROP` is 17.2's: it drives "
            "a real TLS 1.3 client/server flight, ClientHello through Finished plus an "
            "application-data exchange, over the record layer, the extension units "
            "(ssl/extensions_clnt.c/ssl/extensions_srvr.c), the key schedule "
            "(ssl/t1_enc.c/ssl/tls13_enc.c) and the 56 message bodies D529 handed forward. "
            "`RT-CROSS-DSO-STATE` is 17.3's: it raises an ERR through the libssl path and reads it "
            "through the libcrypto path (and the same for CONF), requiring one queue across the "
            "candidate's whole-crate archives, where the authority shares one libcrypto.so.3 via "
            "DT_NEEDED. `RT-DOWNSTREAM-CONSUMER` is 17.4's: it builds a real downstream consumer "
            "against the candidate distribution shell. This stratum owns no exported symbol, so no "
            "differential probe over a symbol set is its evidence. No court is registered in "
            "forensics/tools/gen_frf_courts.py: that registry is the stratum's seal (section 4.2), "
            "as Phase 16 registered its six courts only at 16.6. docs/PHASE-17-SUBPHASES.md "
            "sections 1, 3 and 4 record the measurement and the courts (docs/DECISIONS.md D530)."
        ),
    }

    inputs = [
        InputRef(name="phase-17-plan", path=PLAN),
        InputRef(name="prerequisites", path=PREREQUISITES),
        InputRef(name="probe", path=PROBE_DIR / "rt_cli_bodies_probe.sh"),
    ]
    doc = envelope(kind="phase17-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "pass":
            print(f"  {r['court']:<18} pass   ({r['authority_observations']} observations, "
                  f"{len(r.get('recorded_divergences', []))} recorded divergence(s))")
        else:
            print(f"  {r['court']:<18} FAIL   stage={r.get('stage', 'compare')}")
            for res in r.get("residuals", [])[:12]:
                print(f"      {res['observation']}: authority={res['authority']!r} "
                      f"candidate={res['candidate']!r} ({res['class']})")
    for name, needs in PENDING_COURTS.items():
        print(f"  {name:<24} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
