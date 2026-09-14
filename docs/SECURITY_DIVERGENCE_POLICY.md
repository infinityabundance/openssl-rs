# Security Divergence Policy

Status: **constitution** (Phase 0).

Custodianship is not fossilisation of vulnerabilities. When historical OpenSSL
behaviour differs from a security-fixed authority, the fixed behaviour wins for
production, and the historical behaviour becomes a *recorded trajectory*, never a
reintroduced defect.

## 1. The 3.6.3 → 3.6.4 trajectory

Two authorities are admitted:

| authority | role |
|---|---|
| `openssl-3.6.3-historical` | what extant downstream archaeology observed |
| `openssl-3.6.4-production` | the production target (security-fix release) |

Before the production authority is claimed, an **oracle-vs-oracle** differential
court runs 3.6.3 against 3.6.4 over the shared court families, producing an
oracle/oracle residual atlas. This teaches the system what *legitimate upstream
behavioural evolution* looks like, and prevents wasting effort reproducing a
3.6.3 quirk that upstream itself removed.

The trajectory is recorded through the FRF chain
(Authority → Court → Capture → Residual → Endoduction → Route → Disposition →
Receipt → Claim) so that "why does this behaviour exist?" is always answerable.

## 2. Procedure when historical behaviour differs from the fixed authority

1. **Retain** the historical raw observation, unchanged.
2. **Reproduce** the issue in an isolated oracle-only court if needed.
3. **Admit** the fixed OpenSSL authority.
4. **Establish** the oracle-version trajectory.
5. **Implement** the fixed production behaviour.
6. **Disposition** the historical residual as an oracle-version / security
   evolution — a first-class, nameable outcome, not a suppression.
7. **Never** silently claim historical vulnerable behaviour is production parity.

## 3. Prohibited

- Copying a known memory-safety defect merely to obtain byte-level parity.
- Reintroducing a security regression to match a historical authority.
- Silently reproducing known vulnerabilities.
- Suppressing a failing oracle test without proving the oracle fails identically.

## 4. When compatibility and safety genuinely conflict

If exact compatibility and safety conflict, the conflict is **documented
explicitly** and the parity claim is **narrowed**. It is never hidden. A narrowed
claim is an honest result; a hidden conflict is a defect in the evidence.

The narrowing is recorded as a residual with disposition
`intentional_safe_divergence`, naming:

- the exact obligation affected;
- the authority behaviour reproduced or not;
- the security reason;
- the scope removed from the claim.

## 5. Interpretation of "authority" for security-relevant behaviour

An authority is a *behavioural* reference, not a moral one. Where the authority
contains undefined behaviour, the candidate does **not** reproduce the undefined
behaviour merely because one observed run yielded a particular result. Such cases
are recorded as *compatibility boundaries* (see `docs/RELEASE_GATES.md`
§"Safety testing").
