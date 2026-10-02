# The Phase-22 POD census

Generated from `forensics/atlas/phase22/pod-contract.json` by
`forensics/tools/phase22_pod.py`; every number below is derived, none is typed.

## The corpus

- manual pages: **903** (man1 62, man3 679, man5 3, man7 159)
- generated from a `.pod.in` template: **56** (resolved the way the build does)
- `NAME` entries: **6563**
- SYNOPSIS declarations (man3): **4960**
- man1 command pages: **59**, documented CLI options: **2182**
- environment variables: **53**
- configuration directives: **66**
- default pathnames: **3**
- documented return values: **172**
- deprecation statements: **58**
- provider algorithm identities (man7): **91**

## The claim graph

- claims: **15045**

| kind | class | claims |
|---|---|---|
| CLI_OPTION | EXECUTABLE_CLAIM | 2182 |
| CONCEPT | EXPLANATORY_ONLY | 903 |
| CONFIG_DIRECTIVE | EXECUTABLE_CLAIM | 66 |
| DEFAULT_PATH | EXECUTABLE_CLAIM | 3 |
| DEPRECATION | EXECUTABLE_CLAIM | 58 |
| ENV_VAR | EXECUTABLE_CLAIM | 53 |
| NAME_ENTRY | STRUCTURAL | 6563 |
| PROVIDER_ALGORITHM | EXECUTABLE_CLAIM | 91 |
| RETURN_VALUE | SEMANTIC_TEXT | 172 |
| SYNOPSIS_DECL | STRUCTURAL | 4954 |

| class | claims |
|---|---|
| EXECUTABLE_CLAIM | 2453 |
| EXPLANATORY_ONLY | 903 |
| SEMANTIC_TEXT | 172 |
| STRUCTURAL | 11517 |

## Testability

| kind | probe | claims |
|---|---|---|
| CLI_OPTION | cli-surface | 2182 |
| CONFIG_DIRECTIVE | config-surface | 66 |
| DEFAULT_PATH | config-surface(default_paths) | 3 |
| DEPRECATION | num(DEPRECATEDIN)+tu-ast(attributes) | 58 |
| ENV_VAR | config-surface | 53 |
| NAME_ENTRY | header-atlas+num+tu-ast | 6563 |
| PROVIDER_ALGORITHM | provider-algorithms | 91 |
| SYNOPSIS_DECL | header-atlas+num+tu-ast | 4954 |

`UNTESTABLE` -- claims with no mechanical predicate, and why:

- **EXPLANATORY_ONLY** (903 claims): man7 concept and provider-behaviour prose is explanatory; the mechanically defensible part (NAME, provider identities) is extracted and probed separately
- **SEMANTIC_TEXT** (172 claims): the RETURN VALUES section is prose; whether a documented success value is the value the implementation returns is not decidable from the text without executing the function, so the claim is retained as a quote and no equality probe is asserted

## The reconciliation

- disagreements: **2293**
- man3 `NAME` entries documented: **6202**
- `.num` ABI names in the admitted profile: **6538**
- installed manpage files (22.8's manifest): **903** plus **5660** alias symlinks
- public header/API atlas names not documented by any man3 `NAME` entry (combined count, per-row list not emitted): **19816**

| class | count |
|---|---|
| ATLAS_PUBLIC_NAME_NOT_IN_POD | 1255 |
| POD_CLI_OPTION_MISSING | 80 |
| POD_CONFIG_DIRECTIVE_MISSING | 51 |
| POD_DEFAULT_PATH_MISMATCH | 1 |
| POD_DEPRECATION_MISMATCH | 21 |
| POD_ENVIRONMENT_VARIABLE_MISSING | 8 |
| POD_NAME_NOT_IN_ATLAS | 872 |
| POD_PROVIDER_ALGORITHM_MISSING | 4 |
| RUNTIME_CLI_OPTION_UNDOCUMENTED | 1 |

## find-doc-nits (one instrument, not the oracle)

- `util/find-doc-nits` exit code: 1
- libcrypto names not documented: 1229
- libssl names not documented: 30
- macros undocumented: 45
- reference-to-non-existing links: 27

## Gaps and reductions, named

- man7 concept extraction is partial: the NAME description and the provider `Identities` lists are extracted and probed, but provider-behaviour prose is EXPLANATORY_ONLY and untestable -- it is not turned into an assertion
- RETURN VALUES quotes are SEMANTIC_TEXT: the text is retained but its success/failure semantics are not mechanically decided (UNTESTABLE)
- deprecation extraction is sentence-level and best-effort; a sentence naming several subjects yields the subject adjacent to the verb (recorded, not hidden)
- default-pathname extraction is narrow by construction: only a `F<>` token on a line mentioning a default, which is a mark of the corpus rather than a parse of prose
- `util/find-doc-nits` is one instrument and its stderr carries the pinned container's git-probe usage text; both are retained raw
- `docs/PHASE-22-SUBPHASES.md` section 5 lists a separate `pod-atlas-reconciliation.json`; this plane folds the reconciliation into `pod-contract.json` (the artefact this task names) rather than emitting a second document

SPDX-License-Identifier: Apache-2.0
