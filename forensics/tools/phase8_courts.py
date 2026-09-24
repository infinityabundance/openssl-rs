#!/usr/bin/env python3
"""openssl-rs — Phase 8 courts: the native cryptographic primitives.

Each court is a C probe in `courts/phase8/` compiled **twice** — once against the admitted
authority, once against the candidate distribution shell — and run. The two transcripts are
compared line by line, and every difference is a residual.

The method is Phases 3, 4, 5, 6 and 7's, for the same reason: a unit test encodes what the
author wrote believes the contract is, whereas a probe measures what the authority actually
does, and the comparison is between two *executions* of the same program, so the expectation
cannot drift.

Two registries, because a primitive has two questions
------------------------------------------------------
Every primitive-bearing subphase of this stratum carries **two** courts, and they are not
substitutes for one another (`docs/PHASE-8-SUBPHASES.md` §3.5, `docs/DECISIONS.md` D201):

    RT-DIGEST   the differential court  -> "does the candidate behave like the authority?"
    CT-DIGEST   the correctness court   -> "does the candidate satisfy the construction?"

The `RT-*` shape is this module's own: a probe compiled twice, against the authority and
against the candidate distribution shell, and the two `key=value` transcripts diffed. It
answers *compatibility*, and it cannot answer correctness: two implementations can agree
byte for byte and both be wrong. So the `CT-*` shape is deliberately different and is driven
by `forensics/tools/correctness_vectors.py`: the probe is compiled **once**, against the
candidate alone, and its output is compared with committed expected bytes whose provenance is
recorded per vector. There is no authority transcript in a correctness court, so there is
nothing to diff; a single mismatched vector fails the court loudly.

The two registries below are separate for that reason. A name in `COURTS` must have a probe in
`courts/phase8/`; a name in `CORRECTNESS_COURTS` must have committed vectors in
`forensics/vectors/`. A `CT-*` court whose primitive is not implemented yet is **not**
registered as passing; it is named in `PENDING_CORRECTNESS_COURTS` with what it needs, so the
absence is a statement rather than an omission.

What this stratum's first court has to observe, and why it can observe it at all
----------------------------------------------------------------------------------
Phase 7's first court had to *decide* what a court could see, because its subject — the
fetch store — exports nothing. This stratum's subject is the opposite: every digest, cipher
and key type here is a public function whose whole contract is a value. So the discipline is
not "what can be observed" but **"what must be observed to catch a transcription error"**,
and for a digest that list is longer than it looks:

  * the digest bytes for a message, as hex, so a wrong round constant, rotation or table
    entry is a residual rather than a plausible-looking output;
  * the empty message, because it is the padding path with a zero-length input;
  * the 55/56/64-byte boundary vectors, because that is where the length field and the
    extra-block arm of the padding diverge on a transcription error;
  * the block size and the digest size, as the authority reports them;
  * an `Update` split across two calls against the same bytes in one, because the collector's
    partial-block buffer is a second code path;
  * `Transform` on a non-multiple-of-block input, which the authority accepts and which
    advances the state without touching `num`.

The comparison is a `key=value` line diff, so a missing or extra observation is one residual
rather than a shifted transcript. Addresses are never printed: every observation is a return
code, a length, or a byte comparison the probe performs itself.

Fault boundaries
----------------
A probe cannot compare a crash. Where the authority faults the probe does not call, and the
candidate's safer behaviour is recorded in `docs/SECURITY_DIVERGENCE_POLICY.md`.

A probe also cannot compare a symbol the candidate has not implemented: calling a scaffold
aborts the candidate with a diagnostic. The obligation ledger
(`forensics/tools/phase8_obligations.py`) is where that is recorded; the probe stays on the
implemented surface so that a failure here means a behavioural divergence rather than a
missing symbol.

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import correctness_vectors as cv  # noqa: E402

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

OUT = REPO_ROOT / "artifacts" / "phase8" / "COURTS.json"
GENERATOR = "forensics/tools/phase8_courts.py"
PROBE_DIR = REPO_ROOT / "courts" / "phase8"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
STAGED = REPO_ROOT / "artifacts" / "phase8" / "probes"
RUN_TIMEOUT_S = "60"

# The differential courts, in the order they landed. 8.0 lands the runner with none of them,
# which is the shape 7.0 had: the ledger and the stratum's wiring are evidence, and a court
# arrives in the subphase that gives it something to observe. `RT-DIGEST` lands with 8.1 and
# is declared here in the same commit as its probe, so a runner that names a probe which does
# not exist cannot be committed. (name, probe filename)
COURTS: list[tuple[str, str]] = [
    ("RT-DIGEST", "rt_digest_probe.c"),
    ("RT-CIPHER", "rt_cipher_probe.c"),
    # The allocator-attribution court, and a court of its own because
    # `CRYPTO_set_mem_functions` latches: the first non-zero allocation through the default path
    # clears `allow_customize` for the life of the process, so an installation that is not the
    # first thing a program does answers 0. `rt_cipher_probe.c` allocates long before any cipher
    # arm of its own would run, so the observation cannot be an arm of `RT-CIPHER` (D280).
    ("RT-CIPHER-MEM", "rt_cipher_mem_probe.c"),
    # 8.4's method-table court. It is the first `RT-*` here whose subject is *ownership* rather
    # than arithmetic: the thirty-four `RSA_meth_*`/`RSA_null_method` labels allocate a table,
    # store a pointer in it, or return one. It is also the second court to install a caller
    # allocator, and for the same latching reason it must be its own probe -- see the probe's own
    # note on why it is not a court for the default method, which is slice A's.
    ("RT-RSA", "rt_rsa_probe.c"),
    # 8.5's method-table court. It is the first `RT-*` here whose subject is the DH method table:
    # the twenty-one `DH_meth_*` labels allocate a table, store a pointer in it, or return one, so
    # it is the slice of 8.5 whose prerequisites are already in, exactly as slice B was for 8.4.
    ("RT-DH", "rt_dh_probe.c"),
    # 8.6's method-table and object court. Its subject is the twenty-seven `DSA_meth_*` labels
    # plus the `DSA` object, its parameter and key generation, and the sign/verify pair -- so it
    # is the first `RT-*` here that has to observe a *signature*, and it does so by properties
    # (the two halves in `[1, q)`) and by the verification verdict rather than by value. Three
    # of its refusal arms leave two queue records, which is the shared `err:` label each unit
    # transcribes rather than an early return per failure.
    (
        "RT-DSA",
        "rt_dsa_probe.c",
    ),
    # 8.7's curve-table court. Its subject is the four lookups over `ec_curve.c`'s built-in
    # parameter table and `crypto/evp/ec_support.c`'s two name tables -- `EC_get_builtin_curves`
    # in all four of its call shapes, and the three name lookups in both directions over all
    # eighty-two rows and over their refusals. **The curve constants themselves are not courted
    # here**: `p`, `a`, `b`, `gx`, `gy`, `order`, the cofactor and the seed reach a caller only
    # through `EC_GROUP_new_by_curve_name`, which is the group object and the field arithmetic
    # D334 records as one indivisible landing. Their evidence is
    # `forensics/tools/gen_ec_curves.py` -- which reads every value back from the authority and
    # checks it against the `data[]` array the authority's own struct declares -- and the unit
    # tests in `src/ec/curve.rs`. The probe says so in its own header, because a probe that
    # called a symbol the candidate has not implemented would abort the candidate's side.
    ("RT-EC", "rt_ec_probe.c"),
    # 8.8's registry court. Its subject is `crypto/asn1/standard_methods[]` -- the eleven
    # `EVP_PKEY_ASN1_METHOD` rows D353 landed -- and the `crypto/evp` layer they close over: the
    # five `EVP_PKEY_asn1_*` accessors, `EVP_PKEY_type`, `EVP_PKEY_assign` with
    # `EVP_PKEY_get0_asn1`, the twelve legacy accessors' four refusals, and the
    # `param_missing`/`param_cmp`/`param_copy` columns through a built FFDHE-2048 key. **D372
    # completed the table to the authority's fifteen rows**, so this probe's arms stay as they
    # are -- they print booleans and the eleven `pkey_id`s both sides have always shared -- and
    # the four ECX rows are carried by **`RT-ECX`**, the court below, whose subject they are.
    # The eight `RSA_print`/`DSA_print`/`EC_KEY_print` printers are withheld --
    # `EVP_PKEY_print_private` is absent from the crate's compiled surface -- and so are the
    # three `EVP_PKEY_meth_*` names. The probe's own header states both omissions.
    ("RT-AMETH", "rt_ameth_probe.c"),
    # 8.9's `pem.h` helper court. Its subject is the thirty `crypto/pem/pem_all.c` rows -- the
    # `IMPLEMENT_PEM_*` expansions for the DH, DSA, EC and RSA key families -- together with the
    # PEM plumbing they call (`PEM_bytes_read_bio`, `PEM_do_header`, `PEM_def_callback`,
    # `PEM_ASN1_*`) and `pem_oth.c`'s `PEM_ASN1_read_bio`. The six private-key readers are now
    # **covered**, by `RT-PUBKEY` rather than here (D369): they need `PEM_read[_bio]_PrivateKey`,
    # which `src/pem/pem_pkey.rs` carries, and that probe is the one that drives them. Every writer
    # arm prints a public parameter set's block or, for a private key, only its header lines and
    # round trip.
    ("RT-PEM-KEY", "rt_pem_key_probe.c"),
    # D369's court. Its subject is `crypto/x509/x_pubkey.c`'s object layer and `i2d`/`d2i`
    # public-key family, together with `crypto/pem/pem_pkey.c`'s read half -- the four
    # `PEM_read[_bio]_PrivateKey[_ex]` spellings, the four `PUBKEY` ones and the six `pem_all.c`
    # private-key readers. **Two arms are deliberately absent and the probe's header names them**:
    # the `OSSL_DECODER` leg, whose answer must differ because this crate publishes no provider
    # decoder (`D-DECODER-ABSENT-1`), and a PKCS#8 `PRIVATE KEY` block, for the same reason. The
    # two `PEM_read_bio_Parameters*` spellings are withheld rather than courted, because their only
    # successful arm on this revision is that same decoder.
    ("RT-PUBKEY", "rt_pubkey_probe.c"),
    # D372's court, and the last of 8.8's three. Its subject is the four
    # `crypto/ec/ecx_meth.c` rows D353/D355 withheld from both `standard_methods[]` tables:
    # `ossl_ecx{25519,448}_asn1_meth` and `ossl_ed{25519,448}_asn1_meth` in the ameth table, and
    # `ossl_ecx25519_pkey_method`/`_ecx448_`/`_ed25519_`/`_ed448_pkey_method` in the pmeth one.
    # The arms are the two `find` functions, `EVP_PKEY_type`, both `get0` walks and both
    # `get_count`s -- the four observables `D-PKEY-AMETH-3` named -- plus four fixed
    # `SubjectPublicKeyInfo` decodes that reach the seven per-type `EVP_PKEY_ASN1_METHOD`
    # columns (`ecx_pub_decode`, `ecx_pub_encode`, `ecx_bits`, `ecx_size`, `ecx_security_bits`,
    # `ecd_ctrl`, `ecx_ctrl`). **Three omissions are deliberate and the probe's header names
    # them**: the eight `ossl_*_PUBKEY` internals, which are not in either library's dynamic
    # symbol table and are reached through `d2i_PUBKEY`/`i2d_PUBKEY` instead; the private-key
    # arms, whose evidence is `src/ec/ecx_backend.rs`'s RFC 7748 unit test; and any
    # context-building arm, because `int_ctx_new`'s legacy `pmeth` arm is not this landing's
    # subject (D355).
    ("RT-ECX", "rt_ecx_probe.c"),
    # 8.10's registration-row court, and the arm D386's six landed rows were missing. Its subject
    # is the `OSSL_OP_KEYMGMT` rows (`DH`, `DHX`, `DSA`, `RSA`, `RSA-PSS`, `EC`, the four ECX types,
    # the KDF trio, the four legacy MAC types and `SM2`), the `OSSL_OP_KEYEXCH` rows they gate
    # (`DH`, `ECDH`, `X25519`, `X448`, and the KDF trio) and the `OSSL_OP_KEM` rows (`X25519`,
    # `X448`): it fetches each by type name, builds a `DH` key, the four ECX keys, the `EC`/`SM2`
    # keys and the `RSA`/`RSA-PSS`/`DSA` keys and imports each legacy-MAC key through their own rows
    # with `EVP_PKEY_fromdata`, reads the object accessors, and reaches each exchange and KEM row
    # through the key it built. **D387 landed it with the `DH`/`DHX` rows and named the caveat that
    # it drove only those and the KDF trio**; D388 extended it with the eight ECX rows, D389 with
    # the four MAC rows, D390 with `EC`, `SM2` and `ECDH` and D391 with `RSA`, `RSA-PSS` and `DSA`,
    # each in the same commit as the rows it now drives, so no landed row is named-but-not-driven.
    # **`rt_digest_probe.c` already names `TLS1-PRF`/`HKDF`/`SCRYPT`**, but under `OSSL_OP_KDF` --
    # different rows of a different operation -- so the provider-row coverage join was satisfied
    # while no arm drove the keymgmt, keyexch or KEM rows at all. This is that arm. The probe's own
    # header names what it does not observe and why.
    ("RT-KEYMGMT", "rt_keymgmt_probe.c"),
    # This pass's registration-row court, one operation over: its subject is the four landed
    # `OSSL_OP_SIGNATURE` rows (`HMAC`, `SIPHASH`, `POLY1305`, `CMAC`), which are the legacy-MAC
    # *signature* face of the four key objects `RT-KEYMGMT` drives. `EVP_SIGNATURE_fetch` names no
    # row of any other operation, so without this entry the four would be an unmatched finding the
    # moment they landed. **The court drives the sign path and observes the verify path's refusal**
    # -- the rows publish no `VERIFY` slot, which is the one-directional shape of a MAC rather than
    # a missing arm. `RSA`, `DSA`, `ECDSA`, `EdDSA` and `SM2` rows are not here: their units wait
    # on `providers/common/der/` and `providers/common/securitycheck.c`, and the probe's header
    # names each row's remaining callee.
    ("RT-SIGNATURE", "rt_signature_probe.c"),
    #
    # This pass's court, and the first whose subject is an **encryption** face rather than a
    # signing or key-management one: the `OSSL_OP_ASYM_CIPHER` `RSA` row and the `OSSL_OP_KEM`
    # `RSA` row. `RT-KEYMGMT` drives the `RSA` keymgmt row both key through and `RT-SIGNATURE`
    # the `RSA` signature rows; neither touches the encryption faces, so without this entry the
    # two rows would be `implemented` and named by no observation of their own operation. The
    # probe's header names what it does not observe and why.
    ("RT-ASYM-CIPHER", "rt_asymcipher_probe.c"),
    # This pass's court, and the first whose subject is the **provider dispatch table's parameter
    # and capability face** rather than an algorithm row: the three `OSSL_FUNC_PROVIDER_*` arms
    # the authority's default dispatch publishes and the candidate's does not --
    # `GETTABLE_PARAMS`, `GET_PARAMS` and `GET_CAPABILITIES`
    # (`forensics/authorities/src/openssl-3.6.4/providers/defltprov.c:742-750`). The three public
    # entry points (`src/provider/mod.rs:2386/2400/2498`) already exist and are wired to the
    # provider vtable, so before the sibling landing each answers the core's "no such function"
    # path (`crypto/provider_core.c:1767/1810/1903`): `gettable_params` NULL, `get_params` 0, and
    # `get_capabilities` **1 with the callback never invited** -- the last of which makes the
    # authority's `0` for an unclaimed capability name (and for a callback that refuses an entry)
    # unreachable. The probe drives all three: the `TLS-GROUP`/`TLS-SIGALG` walks through a
    # recording callback plus the walk's own refusal contract, one capability name no arm claims,
    # and the provider's four `gettable_params` definitions and four answered (plus one
    # unanswered) `get_params` keys.
    ("RT-PROVIDER-CAP", "rt_provider_cap_probe.c"),
]

# The correctness courts, and the committed vector sets each checks. `CT-DIGEST` is the
# exemplar for 8.1a's low-level constructions: one file per algorithm under
# `forensics/vectors/`, extracted from the pinned authority's own `evp_test` data by
# `correctness_vectors.py --emit`. (name, algorithms)
CORRECTNESS_COURTS: list[tuple[str, tuple[str, ...]]] = [
    ("CT-DIGEST", ("md4", "md5", "mdc2", "ripemd160", "sha1", "sha224", "sha256", "sha384",
                   "sha512", "whirlpool", "sha256_192", "sha512_224", "sha512_256",
                   "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2s256",
                   "blake2b512", "sm3", "md5_sha1")),
]

# The cipher correctness court, whose vector schema carries a key, an IV and an operation
# rather than a message and a digest. It is driven by `correctness_vectors.run_cipher_court`
# and its sets are the `cipher-vectors-*` files under `forensics/vectors/`.
CIPHER_CORRECTNESS_COURTS: list[tuple[str, tuple[str, ...]]] = [
    ("CT-CIPHER", ("aes", "rc4", "des", "rc2", "bf", "cast5", "idea", "seed", "camellia",
                   "aria", "aria_ccm", "sm4", "sm4_ccm", "sm4_xts", "wrap", "gcm", "gcm_siv",
                   "chacha20_poly1305", "cbchmac", "ccm", "xts", "ocb", "cts")),
]

# The ML-DSA correctness court, and the second plane D409's three ML-DSA rows were missing. Its
# vector schema is neither digest-shaped nor cipher-shaped — a keygen `(seed, public key)`,
# a siggen `(private key, message, context, signature)` and a sigver `(public key, message,
# signature, verdict)` — so it is driven by `correctness_vectors.run_ml_dsa_court` against the
# generator's own record, `forensics/atlas/ct-ml-dsa-vectors.json`, and its inputs are the
# generated header `courts/phase8/ct_ml_dsa_vectors.h`. A signature is up to 4627 bytes, so a
# digest-shaped `forensics/vectors/` file would have to carry it at full width; the record is the
# generator's instead, added the way `CT-CIPHER`'s `cipher-vectors-*` schema was. It is a plain
# list rather than `(name, algorithms)` because there is no per-algorithm `forensics/vectors/`
# file to name.
ML_DSA_CORRECTNESS_COURTS: list[str] = ["CT-ML-DSA"]

# A `CT-*` court the plan names but whose primitive is not implemented yet. It is not a
# registered court: nothing here can pass, and the runner prints each one as PENDING with what
# it needs so that "not run yet" cannot be read as "passed". Each entry names the subphase and
# the prerequisite in one line; the vectors themselves arrive in the subphase that lands the
# primitive, in the same commit, exactly as `RT-*` probes do.
#
# **A reason here is a claim about the crate, so it is reviewed when the subphase it names moves.**
# Two of the four went stale exactly that way and were corrected rather than left: `CT-RSA` named
# "the RSA object and its decode/verify paths" after both had landed (D321, D325, D328), and
# `CT-DH` named "the DH object and the FFC group arithmetic" after both had (D330, D331, D332).
# What each now names is what is actually left, which for both is the vector corpus and its driver.
PENDING_CORRECTNESS_COURTS: dict[str, str] = {
    "CT-RSA": "8.4 -- the RSA object and its sign/verify and key-check paths have landed "
              "(D321, D325, D328), so what remains is the corpus and its driver: PKCS#1's own "
              "test vectors, with Project Wycheproof's RSA known-attack set as the stated "
              "follow-up. An arm that needs the ASN.1 decode path waits on 8.8.",
    "CT-DH": "8.5 -- the DH object layer and the FFC group arithmetic have landed (D330, "
             "D331, D332), so what remains is the corpus and its driver: PKCS#3 and the "
             "authority's own group vectors.",
    "CT-DSA": "8.6 -- the DSA object layer, its method table and the FFC parameter/key "
              "generators they dispatch to have landed (D330, D333), so what remains is the "
              "corpus and its driver: FIPS 186-4's own parameter and key vectors, with the "
              "authority's vectors as the second source. The DER `DSA-Sig-Value` path "
              "(`DSA_sign`/`DSA_verify`) landed with D342 and `RT-DSA` courts it.",
    "CT-EC": "8.7 -- the built-in curve tables and the three lookups over them have landed "
             "(D334), so their evidence is the differential court and the generator; what a "
             "construction court still needs is `EC_GROUP`/`EC_POINT`, which D334 records as "
             "one indivisible landing with the field arithmetic. The recorded corpus is the "
             "authority's own curve vectors plus Project Wycheproof's EC set as a follow-up.",
}


def extra_defs(name: str, libdir: Path) -> list[str]:
    """Per-side build definitions.

    **None.** Every observation `RT-DIGEST` makes is a return code, a size, or a comparison
    between bytes the probe computed and bytes the library produced — so the probe is
    compiled identically on both sides and a difference in the transcript can only be a
    difference in behaviour. `extra_defs` is kept because the runner's shape is Phase 6's
    and a later court here may need one.
    """
    del name, libdir
    return []


def compile_probe(
    src: Path, out: Path, include: Path, libdir: Path, defs: list[str] | None = None
) -> tuple[bool, str]:
    res = run([
        # `-Werror=implicit-function-declaration` is not decoration: without a prototype, C
        # assumes a function returns `int`, so a probe that forgot an include reads a pointer
        # return as its low 32 bits and dereferences it. RT-FETCH learned that on both sides at
        # once, which the runner refused to read as agreement.
        "clang", "-std=c11", "-Wall", "-Werror=implicit-function-declaration", "-O1",
        "-D_GNU_SOURCE",
        *(defs or []),
        "-I", str(include),
        "-o", str(out), str(src),
        "-L", str(libdir), "-lcrypto",
        f"-Wl,-rpath,{libdir}",
    ])
    return res.ok, res.stderr.strip()


def run_probe(binary: Path) -> tuple[str, str, int | None]:
    res = run(["timeout", RUN_TIMEOUT_S, str(binary)])
    code = res.returncode
    if code == 124:
        return res.stdout, res.stderr, None
    return res.stdout, res.stderr, code


def diff(authority: str, candidate: str) -> list[dict]:
    """Line-wise comparison keyed on `key=value`, so a missing or extra line
    produces exactly one residual instead of shifting every following line."""
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


def court(name: str, src: Path, auth, work: Path) -> dict:
    auth_lib = auth.prefix / "lib"
    auth_inc = auth.prefix / "include"

    auth_bin = work / f"{src.stem}.authority"
    cand_bin = work / f"{src.stem}.candidate"

    ok, err = compile_probe(src, auth_bin, auth_inc, auth_lib,
                            extra_defs(name, auth_lib))
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-authority",
                "detail": err.splitlines()[:12]}
    ok, err = compile_probe(src, cand_bin, PHASE2 / "include", PHASE2,
                            extra_defs(name, PHASE2))
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-candidate",
                "detail": err.splitlines()[:12]}

    a_out, a_err, a_code = run_probe(auth_bin)
    c_out, c_err, c_code = run_probe(cand_bin)

    staged = {}
    STAGED.mkdir(parents=True, exist_ok=True)
    for side, srcbin in (("authority", auth_bin), ("candidate", cand_bin)):
        dst = STAGED / f"{srcbin.stem}.{side}"
        if srcbin.is_file():
            shutil.copyfile(srcbin, dst)
            dst.chmod(0o755)
            staged[side] = rel(dst)

    if not a_out.strip():
        return {"court": name, "verdict": "fail", "stage": "authority-run",
                "detail": {"exit_code": a_code,
                           "stderr": a_err.splitlines()[:12]}}

    residuals = diff(a_out, c_out)
    # A probe that died on a signal compared nothing beyond the prefix it managed
    # to print, so two sides dying the same way is not agreement.
    crashed = a_code is None or a_code < 0 or c_code is None or c_code < 0
    return {
        "court": name,
        "probe": rel(src),
        "authority_exit_code": a_code,
        "candidate_exit_code": c_code,
        "crashed": crashed,
        "authority_observations": len([l for l in a_out.splitlines() if "=" in l]),
        "candidate_observations": len([l for l in c_out.splitlines() if "=" in l]),
        "residual_count": len(residuals),
        "residuals": residuals,
        "verdict": (
            "pass" if not residuals and c_code == a_code and not crashed else "fail"
        ),
        "staged_binaries": staged,
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    work = REPO_ROOT / "court" / "phase8"
    work.mkdir(parents=True, exist_ok=True)

    records = []
    for name, filename in COURTS:
        src = PROBE_DIR / filename
        if not src.is_file():
            records.append({"court": name, "verdict": "fail",
                            "stage": "probe-missing", "detail": rel(src)})
            continue
        records.append(court(name, src, auth, work))

    for name, algorithms in CORRECTNESS_COURTS:
        work.mkdir(parents=True, exist_ok=True)
        records.append(cv.run_court(name, algorithms, work_dir=work,
                                    authority_id=auth.id))

    for name, algorithms in CIPHER_CORRECTNESS_COURTS:
        work.mkdir(parents=True, exist_ok=True)
        records.append(cv.run_cipher_court(name, algorithms, work_dir=work,
                                           authority_id=auth.id))

    for name in ML_DSA_CORRECTNESS_COURTS:
        work.mkdir(parents=True, exist_ok=True)
        records.append(cv.run_ml_dsa_court(name, work_dir=work, authority_id=auth.id))

    passed = sum(1 for r in records if r["verdict"] == "pass")
    body = {
        "all_pass": passed == len(records),
        "authority": auth.id,
        "courts": records,
        "summary": {"total": len(records), "pass": passed,
                    "fail": len(records) - passed},
        "claim": (
            "A passing RT-* court means the candidate produced the same observable "
            "transcript as the authority for the behaviours this probe exercises. "
            "It is a differential-compatibility result, NOT cryptographic or "
            "security correctness, and NOT evidence for any behaviour the probe "
            "does not touch (docs/PARITY_MODEL.md). A passing CT-* court means the "
            "candidate's construction produced the committed expected bytes; it is "
            "NOT OpenSSL parity and NOT formal validation (docs/DECISIONS.md D201)."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=REPO_ROOT / "forensics" / "atlas"
                 / auth.id / "symbols-libcrypto.json"),
    ]
    for _name, filename in COURTS:
        inputs.append(InputRef(name="probe", path=PROBE_DIR / filename))
    for _name, algorithms in CORRECTNESS_COURTS:
        inputs.append(InputRef(name="correctness-probe", path=cv.PROBE))
        for algorithm in algorithms:
            inputs.append(InputRef(name=f"correctness-vectors:{algorithm}",
                                   path=cv.VECTOR_DIR / f"{algorithm}.json"))
    for _name, algorithms in CIPHER_CORRECTNESS_COURTS:
        inputs.append(InputRef(name="cipher-correctness-probe", path=cv.CIPHER_PROBE))
        for algorithm in algorithms:
            inputs.append(InputRef(name=f"cipher-correctness-vectors:{algorithm}",
                                   path=cv.VECTOR_DIR / f"{algorithm}.json"))
    for _name in ML_DSA_CORRECTNESS_COURTS:
        inputs.append(InputRef(name="ml-dsa-correctness-probe", path=cv.ML_DSA_PROBE))
        inputs.append(InputRef(name="ml-dsa-correctness-vectors", path=cv.ML_DSA_VECTORS))
        inputs.append(InputRef(name="ml-dsa-vector-inputs",
                               path=PROBE_DIR / "ct_ml_dsa_vectors.h"))
    doc = envelope(kind="phase8-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r.get("plane") == "correctness":
            if r["verdict"] == "pass":
                print(f"  {r['court']:<12} pass   "
                      f"({r['vectors_passed']}/{r['vectors_checked']} vectors)")
            else:
                print(f"  {r['court']:<12} FAIL   stage={r.get('stage', 'vector-mismatch')} "
                      f"({r.get('vectors_failed', '?')} vector(s) failed)")
                detail = r.get("detail")
                if isinstance(detail, dict):
                    print(f"      exit_code={detail.get('exit_code')}")
                    for line in detail.get("stderr", []):
                        print(f"      {line}")
                elif isinstance(detail, list):
                    for line in detail[:8]:
                        print(f"      {line}")
                if r.get("needs"):
                    print(f"      needs: {r['needs']}")
                for f in r.get("failures", []):
                    print(f"      FAIL {f['algorithm']} {f['id']}")
                    print(f"        input    = {f['input_hex'] or '<empty>'}")
                    print(f"        expected = {f['expected_hex']}")
                    print(f"        actual   = {f['actual_hex'] or f['probe_detail']}")
            continue
        if r["verdict"] == "pass":
            print(f"  {r['court']:<12} pass   ({r['authority_observations']} observations)")
        else:
            print(f"  {r['court']:<12} FAIL   stage={r.get('stage', 'compare')}")
            detail = r.get("detail")
            if isinstance(detail, dict):
                print(f"      exit_code={detail.get('exit_code')}")
                for line in detail.get("stderr", []):
                    print(f"      {line}")
            elif isinstance(detail, list):
                for line in detail[:8]:
                    print(f"      {line}")
            for res in r.get("residuals", [])[:12]:
                print(f"      {res['observation']}: authority={res['authority']!r} "
                      f"candidate={res['candidate']!r} ({res['class']})")
    for name, needs in PENDING_CORRECTNESS_COURTS.items():
        print(f"  {name:<12} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']}")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
