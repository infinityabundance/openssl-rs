# failure:runtime-functional-atlas:candidate:ewftools

A minimized reproducer for one candidate-specific downstream failure.

- consumer: `ewftools`
- atlas: `runtime-functional-atlas`
- subject: `candidate`
- residual class: `runtime-failure`
- failure class: `load-failure`
- authority value: `L7-functional`
- candidate value: `L4-linked`
- first divergent observation: candidate reached L4-linked where the authority reached L7-functional: the candidate fell below the authority-applicable baseline (the rebuilt pristine tree holds no program at ewftools/.libs/ewfverify)
- reproduction: exact (the candidate's own build is exercised against the candidate's own install prefix)

The program is standalone and deterministic: it calls one OpenSSL API and prints its result on stdout, and it `dlopen`s nothing and touches no network. `build.sh` compiles it against `$OPENSSL_PREFIX` (`/work/artifacts/phase2/install` for the candidate, the admitted authority prefix for the authority); `run.sh` runs it with `LD_LIBRARY_PATH` pointed at that prefix. Building and running it against both prefixes demonstrates the differential.
