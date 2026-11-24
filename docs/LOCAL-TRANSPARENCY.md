# Local transparency: what B1 can and cannot establish

**Status of B1: `PARTIAL`.** The item is split into two halves, and only one of
them ran.

| half | what it is | status |
|---|---|---|
| **B1a** | deploy a pinned POSIX-backed `rekor-tiles` v2 instance, publish one real frozen ETP statement through the supported `hashedrekord` path, and archive the service's own binding, inclusion and checkpoint evidence | **`NOT_RUN`** |
| **B1b** | implement the RFC 6962 / C2SP verification rules offline and run the applicable §B.24 corruption controls against a log whose identity is declared to be `FIXTURE-1` | verified, with the limits in §11 |

This document is normative for both halves. It does not upgrade B1a: a fixture is
not a service, and no sentence here may be read as an admission of Rekor, a log
key, a witness or a timestamp authority.

The records are `evidence/b1/PREFLIGHT.json` (B1a), `evidence/b1/FIXTURE.json`,
`evidence/b1/PUBLICATION.json` and `evidence/b1/CONTROLS.json` (B1b), produced
deterministically by `evidence/b1/build_evidence.py`. The verifier is
`forensics/tools/tlog.py`; its controls are
`forensics/tools/tests/test_tlog.py`.

---

## 1. The admitted-service requirement, and why B1a is `NOT_RUN`

§B.30 B1 asks for a **pinned POSIX-backed Rekor v2 test instance**. §B.21 permits a
local POSIX instance for development and adversarial experiments but never
presents it as independent public accountability. §B.10 requires authenticated
service metadata: an active shard URL is never a permanent trust assumption, and
the default public signing configuration is not assumed to select v2. §B.31 makes
a working integration, correct DSSE-to-`hashedrekord` binding and independent
checkpoint/inclusion verification infrastructure-admission items.

None of that is available in this venue. `evidence/b0/REGISTRY.json` records
four separate presence facts: **14 pinned, 0 installed, 0 executable, 0 services
reachable**. The preflight for B1a repeats them with their sources:

| absence | evidence |
|---|---|
| no `rekor-server`, `rekor-cli` or `rekor-tiles` executable | `evidence/b0/REGISTRY.json#/presenceCheck`, `command -v` returned absent |
| no Rekor client, `cosign` or Sigstore client | same |
| no TSA (`tsget` absent; `/usr/bin/openssl` is a TLS toolkit, not an authority) | same |
| no Rekor endpoint or log key outside `docs/` | tracked-path search, same |
| no network | this item made no request; nothing was fetched or installed |
| **no digest for the POSIX server asset** | §B.3.2 records only the `linux/amd64` `rekor-server-aws` asset of v2.4.2, `sha256:3af252cd…61e8a6`; that is a different build from the POSIX backend this project uses (B0 receipt §3) |
| **SCF-1** | the Sigstore `signing_config` inspected 2026-10-22 advertised a **v1** endpoint; a recent client does not imply a v2 service (`evidence/b0/SERVICE-CONFIGURATION.json`) |

B1a therefore records `status: NOT_RUN` with the prerequisites B0 lists
(`TA-B1`, the POSIX-digest gap, authenticated service metadata, the
`hashedrekord` representation, `TA-B2`, `TA-B5`) and the commands that would run
once a pinned instance exists. Those commands are **not executed and are not
evidence**:

1. `sha256sum <pinned-posix-rekor-server-asset>` and compare with a digest
   recorded for **that exact asset** before execution (§B.3.2).
2. `<pinned-rekor-server> serve --help` and `<pinned-client> upload --help`:
   read the exact API version and flags from the admitted binary, not from
   documentation (§B.5).
3. `<pinned-rekor-server> serve --storage posix --posix.path <dir> --log.key
   <key>` with the hostname and port read from the binary's help.
4. `<admitted-client> upload --type hashedrekord --artifact
   evidence/a9/STATEMENTS/a8-shard-000.json … --rekor_server <url>`, with the
   digest derived from the exact DSSE envelope (§B.3.3 T3).
5. `tlog.py checkpoint --file <checkpoint> --origin <origin> --key-name <key>
   --key-hex <hex> --log <mirror>` and `tlog.py verify-inclusion --log <mirror>
   --index <n> --size <n> --leaf evidence/a9/STATEMENTS/a8-shard-000.json
   --proof <proof> --checkpoint <checkpoint> --key-name <key> --key-hex <hex>`.

The fifth command is exact and executable today; the first four contain
placeholders because the binary's interface is not available and is not guessed.
**Enforced by** `PREFLIGHT.json` (`status: NOT_RUN`, `prerequisites`, `plannedCommands`)
and `test_tlog.Fixture` / the B1 receipt; no code path in this repository starts a
Rekor service.

---

## 2. The fixture's identity

The offline half runs against **`FIXTURE-1`**. The identity appears in every
record (`"identity": "FIXTURE-1"`), every checkpoint origin is `FIXTURE-1`, and
every record carries `"admittedService": false`. The labels are
`FIXTURE-1`, `test-only`, `not-rekor-tiles`, `no-log-key`, `no-witness`,
`no-production-signature`.

`FIXTURE-1` is a six-leaf RFC 6962 Merkle tree written in the C2SP `tlog-tiles`
layout of §B.3.2:

| leaf | kind | content |
|---:|---|---|
| 0 | real statement | exact bytes of `evidence/a9/STATEMENTS/a1-sarif.json` |
| 1 | real statement | exact bytes of `evidence/a9/STATEMENTS/a5-admission.json` |
| 2 | real statement | exact bytes of `evidence/a9/STATEMENTS/a7-delta.json` |
| 3 | real statement (published) | exact bytes of `evidence/a9/STATEMENTS/a8-shard-000.json` |
| 4 | synthetic, test-only | generated from the fixed seed `openssl-rs/b1/fixture-1/seed/v1` |
| 5 | synthetic, test-only | same seed, different index |

The two synthetic leaves make the tree's right edge non-perfect (size 6 is not a
power of two) and are labelled as non-evidence. The real leaves are the committed
statement bytes, verified by A9's reader; the producer re-hashes each subject file
(8,699,144 bytes for the published statement's SARIF subject) and refuses a
mismatch. **Enforced by** `TL_REFUSED_BINDING` and
`test_tlog.Fixture.test_the_real_leaves_are_the_frozen_a9_statement_bytes`.

The fixture is **not** the admitted service. It is not `rekor-tiles`, it has no
HTTP API, no `hashedrekord` entry, no integrated time, no log key, no witness and
no production signature. Its only signer is A10's fixed public test key
(§6). **Enforced by** the `admittedService: false` field in every record and
`test_tlog.Fixture.test_the_identity_is_fixture_1_and_not_an_admitted_service`.

---

## 3. Hashing

The construction is RFC 6962 §2.1, quoted verbatim:

> `MTH({}) = SHA-256().`
>
> `MTH({d(0)}) = SHA-256(0x00 || d(0)).`
>
> For n > 1, let k be the largest power of two smaller than n:
> `MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])).`

The empty tree is `SHA-256("")`; a leaf is hashed with the `0x00` domain prefix
and an interior node with `0x01`. The prefixes are not interchangeable, and a
leaf hash is never passed where an interior hash is required.
**Enforced by** `tlog.leaf_hash`, `tlog.node_hash`,
`tlog.empty_tree_root`, `TL_REFUSED_ROOT` for a malformed root, and
`test_tlog.HashingVectors` (hand-computed three-, four- and five-leaf roots using
`hashlib` alone).

**Vectors.** RFC 6962 gives the construction and worked tree shapes but there are
**no official hash test vectors**; the C2SP `tlog-tiles` / `tlog-checkpoint` vector
files were not available offline in this venue. The tests therefore use the RFC's
equations with independently computed values and generated cases at tile
boundaries. They are not conformance vectors and are not presented as such.
**Enforced by** `test_tlog.HashingVectors` and the caveat in
`test_tlog.DocumentSynchronisation`.

---

## 4. Inclusion proofs

The audit path is RFC 6962 §2.1.1:

> `PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])` for `m < k`;
>
> `PATH(m, D[n]) = PATH(m, D[k:n]) : MTH(D[0:k])` for `m >= k`;
>
> `PATH(m, D[1]) = {}`.

Generation is `tlog.inclusion_path` for a list of leaf hashes and
`TiledLog.inclusion_proof` for a tile store. Verification is the §2.1.3 node
accumulation: start from the leaf hash, combine each sibling left or right
according to `fn`/`sn`, refuse an excess element when `sn == 0`, refuse a
truncated path when `sn != 0` after the loop, and compare the result with the
authenticated root. The leaf input is the **statement bytes**, never the tile
server's copy of the leaf; the tile store is consulted only for the binding check
and the sibling hashes.

| refusal | condition | enforced by |
|---|---|---|
| `TL_REFUSED_INDEX` | index not an integer in `0 <= index < size` | `tlog.verify_inclusion`, `test_tlog.InclusionProofs.test_wrong_index_and_out_of_range_are_distinguished` |
| `TL_REFUSED_PROOF` | a non-32-byte sibling, an excess element, a truncated path, or a reconstructed root different from the authenticated one | `tlog.verify_inclusion`, `test_tlog.InclusionProofs.test_excess_and_truncated_proofs_are_refused` |
| `TL_REFUSED_ROOT` | the authenticated root is not 32 bytes | `tlog.verify_inclusion` |

The verifier checks both directions in the tests: every index for every size
1–33, and sizes 255/256/257/300 across the first tile boundary, with the
recursive and tile-based proofs required to agree.
**Enforced by** `test_tlog.InclusionProofs.test_every_index_verifies_for_sizes_one_to_thirty_three`
and `test_tlog.InclusionProofs.test_tile_reconstruction_agrees_with_the_recursive_path`.

---

## 5. Consistency proofs

The proof is RFC 6962 §2.1.2:

> `PROOF(m, D[n]) = SUBPROOF(m, D[n], true)`
>
> `SUBPROOF(m, D[m], true) = {}`
>
> `SUBPROOF(m, D[m], false) = {MTH(D[m])}`
>
> For `m < n`, with `k` the largest power of two smaller than `n`:
> `SUBPROOF(m, D[n], b) = SUBPROOF(m, D[0:k], b) : MTH(D[k:n])` if `m <= k`;
> `SUBPROOF(m, D[n], b) = SUBPROOF(m, D[k:n], false) : MTH(D[0:k])` if `m > k`.

Generation is `tlog.consistency_path` and `TiledLog.consistency_proof`.
Verification runs the same recursion in the same order and returns two hashes:
the hash of the larger span and the hash of the earlier tree's portion inside it.
Both must match — `big == root_n` and `small == root_m`. The second equality is
not optional: without it a proof could reconstruct the later root from different
leaves and say nothing about the earlier tree. This is the obligation the RFC's
node-accumulation form discharges by starting from `root_m`.

A size decrease is not a consistency failure; it is `TL_REFUSED_ROLLBACK` on the
checkpoint path (§6). A larger size with no proof is
`TL_REFUSED_CONSISTENCY`, and a proof that reconstructs either root incorrectly is
also `TL_REFUSED_CONSISTENCY`.
**Enforced by** `tlog.verify_consistency`, `test_tlog.ConsistencyProofs`
(every growth pair up to 33, both power-of-two and non-power-of-two `m`, tile
boundaries, and both-root mutation).

---

## 6. The checkpoint and the note signature

§B.3.2 records the pinned shape:

> A checkpoint body is exactly three mandatory lines — origin, tree size as ASCII
> decimal, base64 root hash — followed by optional extension lines, an empty line
> and one or more note signature lines.

The note text is therefore:

```
<origin>\n
<tree size>\n
<base64 root hash>\n
[<extension line>\n …]
\n
```

The terminating empty line is part of the signed bytes. A signature line is
`— <name> <base64(key hash || signature)>` (U+2014 EM DASH, space), where the key
hash is the first four bytes of `SHA-256(name)`. The verifier selects the key by
**policy** (`key_name` from the caller), never by the name in the note, and
requires the name and key hash to agree before checking the signature over the
exact note text with `hmac.compare_digest`.

**The signature is HMAC-SHA256 with A10's fixed public test key.** It is not an
Ed25519 log key, not a cosignature, and not a production signature. It proves the
note bytes are unchanged and that the test key signed them; it does **not** prove
an independent operator signed them. There is no witness, no quorum and no
cosignature. **Enforced by** `tlog.sign_checkpoint`,
`tlog.verify_checkpoint`, the `testOnly` / `notALogKey` fields in
`PUBLICATION.json`, and `test_tlog.Checkpoints.test_an_unsigned_checkpoint_is_refused`.

| refusal | condition | enforced by |
|---|---|---|
| `TL_REFUSED_CHECKPOINT` | the body is not the three-mandatory-line form with a terminating empty line and signature lines | `tlog.parse_checkpoint_body`, `test_tlog.Checkpoints.test_a_malformed_body_is_refused` |
| `TL_REFUSED_CHECKPOINT_SIGNATURE` | unsigned, malformed signature line, wrong name, wrong key hash, or a signature that does not verify over the exact note text | `tlog.verify_signature`, `test_tlog.Checkpoints.test_a_wrong_key_name_or_key_is_refused` |
| `TL_REFUSED_ORIGIN` | the origin is malformed or is not the expected log identity | `tlog.verify_checkpoint`, `test_tlog.Checkpoints.test_a_wrong_origin_is_refused` |
| `TL_REFUSED_SIZE` | the size line is not canonical decimal or is above the bound | `tlog.parse_checkpoint_body`, `test_tlog.Checkpoints.test_a_malformed_body_is_refused` |
| `TL_REFUSED_ROOT` | the root line is not 32 bytes or is not the root recomputed from the tiles | `tlog.verify_checkpoint`, `test_tlog.Checkpoints.test_a_wrong_root_is_refused` |
| `TL_REFUSED_ROLLBACK` | the new size is smaller than the accepted size | `tlog.verify_checkpoint`, `test_tlog.Checkpoints.test_rollback_split_view_and_consistency` |
| `TL_REFUSED_SPLIT_VIEW` | equal sizes carry different authenticated roots (equivocation) | `tlog.verify_checkpoint`, same test |
| `TL_REFUSED_CONSISTENCY` | a larger size has no valid consistency proof | `tlog.verify_checkpoint`, same test |

The fixture's chain is size **2 → 5 → 6**, all signed by the test key. The
published head is size 6, root
`e9a8ad0126e834c0ec34fed464572772d3f3c2d3501198239a1a5554324c540f`.
**Enforced by** `test_tlog.Fixture.test_the_checkpoints_verify_as_a_chain`.

---

## 7. The tile layout

§B.3.2 records the layout:

> A tile at level `l`, index `n` holds the 256 hashes
> `MTH(D[(n·256 + i)·256^l : (n·256 + i + 1)·256^l])` for `i` in 0..=255. A full
> tile is exactly 256 hashes, 8,192 bytes.
>
> Tile paths are `<prefix>/tile/<L>/<N>[.p/<W>]`; `<N>` is encoded as zero-padded
> 3-digit path elements of which all but the last begin with `x`
> (`1234067` → `x001/x234/067`); `<W>` is the partial-tile width, 1–255. Entry
> bundles are `<prefix>/tile/entries/<N>[.p/<W>]` and are sequences of big-endian
> `uint16` length-prefixed entries.

Implemented as:

* **Entry bundles (data tiles)** — `tile/entries/<N>` with a `.p/<W>` suffix for a
  partial tile. Each entry is a two-byte big-endian length followed by that many
  bytes. At most 256 entries per tile. **Enforced by** `tlog.encode_entry_bundle`,
  `tlog.decode_entry_bundle`, `TL_REFUSED_TILE`, and
  `test_tlog.Tiles.test_entry_bundle_roundtrip_and_length_prefix`.
* **Hash tiles** — `tile/<L>/<N>` with a `.p/<W>` suffix for a partial tile. Level
  0 holds the leaf hashes; level `l > 0` holds the `floor(size / 2^l)` complete
  256^l-leaf subtree hashes. A partial right edge is not stored at a level it does
  not complete; the reader recomputes it from lower tiles. **Enforced by**
  `tlog.build_hash_tiles`, `tlog.TileStore`, `TL_REFUSED_TILE`, and
  `test_tlog.Tiles.test_hash_tiles_hold_complete_subtrees_only`.
* **Path encoding** — `1234067` becomes `x001/x234/067`; `0` becomes `000`;
  `256` becomes `x000/256`. **Enforced by** `tlog._index_segments` and
  `test_tlog.Tiles.test_the_recorded_index_encoding`.
* **Untrusted tiles** — a downloaded tile is not trusted until its cryptographic
  relationship to an authenticated checkpoint is checked: the tiles must
  reconstruct the checkpoint root, and every entry bundle must agree with the
  level-0 hash tile. **Enforced by** `tlog.TileStore.verify_tiles`,
  `TL_REFUSED_ROOT`, `TL_REFUSED_TILE`, and
  `test_tlog.Tiles.test_a_corrupted_hash_tile_does_not_reproduce_the_root`.
* **Earlier checkpoints from a wider mirror** — a reader verifying size 2 against a
  store built for size 6 reads the prefix of the wider tile, not a tile re-cut for
  size 2. **Enforced by** `TileStore._read_prefix` and
  `test_tlog.InclusionProofs.test_tile_boundary_leaves_verify`.

---

## 8. What was published, and what the binding is

`PUBLICATION.json` records exactly one statement:

| field | value |
|---|---|
| statement | `evidence/a9/STATEMENTS/a8-shard-000.json` (714 bytes) |
| statement SHA-256 | `ea67963abf16e9b1e33a86d0eec5e35354f3a890497055867e942eac41d22582` |
| leaf index | **3** |
| leaf hash | `d634ef880585fd724608819941c9717ddaf3b5081508649df21b86771fdd13ad` |
| tree size | **6** |
| root | `e9a8ad0126e834c0ec34fed464572772d3f3c2d3501198239a1a5554324c540f` |
| inclusion proof | 3 elements, verified |
| checkpoint | size 6, signed by `FIXTURE-1 test-only hmac-sha256`, verified |
| consistency | 2 → 5 → 6 verified; an independent 2 → 6 proof verified |

The binding has three parts:

1. **Statement to leaf** — the leaf payload is the exact statement bytes, so
   `sha256(statement)` is the leaf payload digest and `SHA-256(0x00 || statement)`
   is the leaf hash. **Enforced by** `TL_REFUSED_INCLUSION_OF_ABSENT_LEAF` and
   `test_tlog.Fixture.test_the_published_statement_is_included_and_bound`.
2. **Statement to subject** — A9's reader re-hashes the subject file named by the
   statement; the published statement's subject digest is
   `b16d376ae0b2fa5483650f8019eada15102fcae580b0a46419b13e7ee98450ed`, the digest
   of the 8,699,144-byte SARIF subject. **Enforced by**
   `TL_REFUSED_BINDING`, `tlog.verify_subject_binding`, and the subject-digest
   control in `CONTROLS.json`.
3. **Envelope recorded, not used as a log entry** — the exact A10 DSSE envelope is
   verified over its PAE (`envelopeSha256
   5bf418cc…` and the PAE digest are recorded), but **no `hashedrekord` entry was
   produced**. The admitted client's derivation of the `hashedrekord` digest from
   the exact envelope (§B.3.3 T3) is B1a and is `NOT_RUN`. **Enforced by** the
   `hashedrekordPath.status: NOT_RUN` field in `PUBLICATION.json`.

The leaf is the statement, not a Rekor `hashedrekord` entry. That difference is
the whole reason B1a cannot be marked done.

---

## 9. Corruption controls and their canaries

`CONTROLS.json` records 36 rows: **21 run offline**, **15 `NOT_RUN`**. Every run
row fired and every run row has an accepted canary. A canary disables the named
check and must then accept the same input; `scope: verifier` means the whole call
returns without refusal, `scope: check` means the named check alone returns
without refusal (a malformed proof or a binding mismatch cannot become a valid
proof merely by disabling its own check, and the row says so).

| item | control | refusal | canary |
|---:|---|---|---|
| 1 | tampered Merkle leaf | `TL_REFUSED_PROOF` | verifier, root disabled |
| 2 | leaf index `6` in size 6 | `TL_REFUSED_INDEX` | check, index disabled |
| 2 | proof for index 3 claimed at index 2 | `TL_REFUSED_PROOF` | verifier, root disabled |
| 3 | sibling order swapped | `TL_REFUSED_PROOF` | verifier, root disabled |
| 4 | truncated proof | `TL_REFUSED_PROOF` | verifier, proof+root disabled |
| 5 | excess proof element | `TL_REFUSED_PROOF` | verifier, proof+root disabled |
| 6 | signed wrong checkpoint root | `TL_REFUSED_ROOT` | verifier, root disabled |
| 7 | signed checkpoint size 7 over 6 leaves | `TL_REFUSED_SIZE` | check, size disabled; next refusal `TL_REFUSED_TILE` |
| 8 | checkpoint signed with another key | `TL_REFUSED_CHECKPOINT_SIGNATURE` | verifier, signature disabled |
| 9 | checkpoint from `OTHER-LOG` | `TL_REFUSED_ORIGIN` | verifier, origin disabled |
| 10 | checkpoint from `FIXTURE-1-shard-002` | `TL_REFUSED_ORIGIN` | verifier, origin disabled |
| 11 | incorrect DSSE PAE digest | **`NOT_RUN`** | needs the admitted client's `hashedrekord` derivation (§B.5, §B.3.3 T3) |
| 12 | valid leaf for an unrelated statement | `TL_REFUSED_INCLUSION_OF_ABSENT_LEAF` | verifier, absent-leaf+root disabled |
| 13 | unsupported protocol version | **`NOT_RUN`** | needs the admitted service's version negotiation (§B.5, §B.10) |
| 14 | 100-byte hash tile | `TL_REFUSED_TILE` | check, tile disabled |
| 15 | entry bundle reordered, head re-signed | `TL_REFUSED_INCLUSION_OF_ABSENT_LEAF` | check, the reordered log's own leaf is valid |
| 16 | partial tile declares width 3, carries 4 | `TL_REFUSED_TILE` | check, declared width disabled |
| 17 | corrupted hash tile in the mirror | `TL_REFUSED_ROOT` | verifier, root disabled |
| 18 | size-2 checkpoint replayed after size 6 | `TL_REFUSED_ROLLBACK` | verifier, rollback disabled |
| 19 | same-size conflicting checkpoints | `TL_REFUSED_SPLIT_VIEW` | verifier, split-view disabled |
| 20 | invalid 5 → 6 consistency proof | `TL_REFUSED_CONSISTENCY` | verifier, consistency disabled |
| — | duplicate leaf append | `TL_REFUSED_DUPLICATE_LEAF` | check, duplicate disabled |
| — | subject digest not the subject bytes | `TL_REFUSED_BINDING` | check, binding disabled |

Items **21–33** are `NOT_RUN`, each with the clause that would exercise it:
witness state and credentials (21–23, §B.11/§B.21), timestamp imprint, authority
and backdating (24–26, §B.9 — B2), campaign omission (27, §B.13–B.14 — B3),
archive, revocation and trust-root rotation (28–30, §B.17/§B.19/§B.10 — B4/B6),
and interrupted publication, service unavailability and retry ambiguity (31–33,
§B.10/§B.23 — B1a). No witness, timestamp, campaign or service exists.

A control that fires proves this verifier refuses that corruption. It does not
prove a live Rekor service behaves as `FIXTURE-1` does, and it does not earn
credit for a defect class the verifier cannot see. **Enforced by**
`evidence/b1/CONTROLS.json`, `test_tlog.Fixture.test_every_offline_control_fired_and_every_canary_was_accepted`,
and `test_tlog.Fixture.test_the_declared_control_items_are_present`.

---

## 10. Refusal table

Every code is stable and names the conclusion it prevents. `tlog.REFUSALS`
carries the same text; the document test requires each name to appear here.

| code | condition | prevents |
|---|---|---|
| `TL_OK` | the requested verification succeeded | — |
| `TL_REFUSED_USAGE` | no command, or a missing required argument | that an incomplete invocation is read as a result |
| `TL_REFUSED_IO` | a required file is absent or unreadable | that a missing record is treated as an empty record or as agreement |
| `TL_REFUSED_PROOF` | malformed, truncated, excess, or non-reconstructing inclusion proof | that a leaf is reported included in a tree whose root it does not reconstruct |
| `TL_REFUSED_ROOT` | a root is not 32 bytes, or a checkpoint root is not the recomputed root, or corrupted mirror data changes it | that an unauthenticated or corrupted root authorises inclusion |
| `TL_REFUSED_INDEX` | an index is not an integer in `0 <= index < size` | that an out-of-range index is reported as a leaf position |
| `TL_REFUSED_SIZE` | a size is negative, non-canonical, above the bound, or larger than the tile store proves | that a size the log cannot have reached is read as authenticated |
| `TL_REFUSED_ORIGIN` | a malformed origin, the wrong log identity, or two origins compared (including shards) | that another log's or shard's checkpoint is read as this log's state |
| `TL_REFUSED_CHECKPOINT` | a body is not the pinned form with a terminating empty line and signatures | that a truncated or extension-confused document is read as a checkpoint |
| `TL_REFUSED_CHECKPOINT_SIGNATURE` | unsigned, malformed line, wrong name/key hash, or a signature that does not verify | that an unsigned or differently signed checkpoint is read as the policy key's |
| `TL_REFUSED_CONSISTENCY` | missing, malformed, or non-reconstructing consistency proof | that a larger tree gets append-only credit without a valid relationship |
| `TL_REFUSED_ROLLBACK` | a smaller size follows an accepted larger one | that a stale checkpoint silently replaces later accepted state |
| `TL_REFUSED_SPLIT_VIEW` | equal sizes with different authenticated roots | that an equivocating head is accepted as growth |
| `TL_REFUSED_TILE` | a missing/malformed tile, wrong partial width, bad uint16 length, or entry/hash-tile disagreement | that malformed tiles, reordered bundles or inconsistent mirrors are read as the log |
| `TL_REFUSED_DUPLICATE_LEAF` | appending bytes already present | that one statement is counted as two independent entries |
| `TL_REFUSED_INCLUSION_OF_ABSENT_LEAF` | the leaf at the claimed index is not the statement being verified | that a valid proof for one entry is read as inclusion of another statement |
| `TL_REFUSED_BINDING` | a subject digest does not match the subject bytes, or the payload digest is not the leaf payload | that a statement about one artefact is bound to another's bytes |

**Enforced by** `test_tlog.RefusalVocabulary.test_every_refusal_code_fires` (one
triggering case per code) and `test_tlog.DocumentSynchronisation`.

---

## 11. What the fixture establishes, and what it does not

**It establishes** that `forensics/tools/tlog.py`, against `FIXTURE-1`:

* recomputes the RFC 6962 root from the C2SP tile layout and matches the signed
  checkpoint;
* verifies the published statement's leaf hash, inclusion proof and checkpoint;
* verifies the 2 → 5 → 6 consistency chain and an independent 2 → 6 proof;
* refuses each offline §B.24 corruption with the documented code, and accepts the
  same input when the named check is disabled (the canary);
* reproduces byte-for-byte from the committed inputs and a fixed seed.

**It does not establish** that:

* `FIXTURE-1` is `rekor-tiles` v2.4.2, or any Rekor service;
* any log operator signed anything: the only key is A10's test-only HMAC key;
* an independent witness, quorum or cosignature exists: there is no independent
  witness and none does at any `n`;
* a trusted signing time exists: no RFC 3161 token was requested (§B.9, B2);
* a real `hashedrekord` entry was created, or that the admitted client's digest
  derivation is correct (§B.5, §B.3.3 T3, B1a);
* the tiles came from a service, a mirror or a network;
* any Rekor admission, submission or witness will succeed;
* the two synthetic leaves are evidence of anything.

The fixture's safety evidence and its compatibility evidence are different axes:
a green control is not a conformance result, and a reproducible fixture is not a
deployment.

---

## `NOT_RUN`

* Any download, installation, execution or configuration of `rekor-tiles`, a
  Rekor client, `cosign`, a Sigstore client, a witness or a TSA.
* Any network request, including a fresh `signing_config` inspection and the
  §B.5 security-advisory recheck.
* Any log-key generation, production checkpoint signature or cosignature.
* Any `hashedrekord` submission, log entry, integrated time or Rekor bundle.
* §B.24 items 11 and 13, and 21–33 (witness, timestamp, campaign, archive,
  revocation, trust-root rotation and live-service controls).
* Any RFC 3161 timestamp request or token verification (B2).
* Any independent witness admission, quorum evaluation or split-view test against
  real infrastructure (B5).
* Any claim that `FIXTURE-1` is an admitted service, or that the offline verifier
  is an independent implementation of the admitted Rekor client.
* Independent review, BOUNDARY and SEAL evidence, and the Rust suite (`src/` was
  not modified).

---

## 12. Reproducing the records

```
python3 evidence/b1/build_evidence.py            # writes the four records and the fixture tree
python3 evidence/b1/build_evidence.py --check    # compares; zero on a byte-identical rebuild
python3 forensics/tools/tlog.py prove --log evidence/b1/fixture --index 3 --size 6
python3 forensics/tools/tlog.py verify-inclusion --log evidence/b1/fixture \
  --index 3 --size 6 --leaf evidence/a9/STATEMENTS/a8-shard-000.json \
  --proof evidence/b1/fixture/inclusion-3-at-6.json \
  --checkpoint evidence/b1/fixture/checkpoint-6.note --origin FIXTURE-1 --test-only-key
python3 forensics/tools/tlog.py verify-consistency \
  --checkpoint1 evidence/b1/fixture/checkpoint-5.note \
  --checkpoint2 evidence/b1/fixture/checkpoint-6.note \
  --proof evidence/b1/fixture/consistency-5-6.json --origin FIXTURE-1 --test-only-key
```

The `--test-only-key` flag is explicit: there is no implicit key selection, and
the CLI prints that the key is A10's test key and not a trust root.
**Enforced by** `test_tlog.CommandLine` (exit 0/1/2 and the printed code) and
`test_tlog.Fixture.test_the_committed_bytes_are_the_current_build`.
