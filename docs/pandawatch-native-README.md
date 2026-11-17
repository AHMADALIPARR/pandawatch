# PANDAWATCH — Native Trust Geometry Reference v0.1

Source-only implementation of the common authorization and trust-boundary
invariants discussed for PANDAWATCH X-RAY. It is **not** an exploit tool, an OS
penetration predictor, or a production-ready enforcement service.

## Files

- `Trust.als`: Alloy 6 bounded model of authentication, active/unrevoked sessions,
  origin binding, authorization, device trust, proxy-independent policy,
  protected transitions, PQC-only policy, bounded message sizes, key release,
  credential disclosure avoidance, and temporal unblocking.
- `Trust.agda`: Agda `--safe --without-K`, proof-carrying admissions and a
  route-independence theorem. Only properties of this abstract model are proved.
- `geometry.fut`: Futhark dense Boolean reachability and iterative propagation
  of nonnegative risk labels; structural graph analysis, not an exploit oracle.
- `proxy.awk`: Portable POSIX AWK rolling per-account failure window. A route
  label is recorded but never grants authority. Produces a deny/step-up/allow
  recommendation; no live traffic handling.
- `tests/proxy.tsv`: deterministic input; `tests/proxy.expected.tsv`: oracle.

## Verification

```sh
awk -f proxy.awk tests/proxy.tsv > /tmp/pandawatch-proxy.tsv
diff -u tests/proxy.expected.tsv /tmp/pandawatch-proxy.tsv
agda --safe Trust.agda
futhark check geometry.fut
# In Alloy 6: open Trust.als and invoke every check and run command.
```

## Interpretation and important limits

Alloy checks are *bounded*: `UNSAT` means no counterexample in the specified
scope, not that an arbitrary binary or device is secure. Several assertions
mirror enforcement facts intentionally; production verification must build
separate observed transition predicates and establish the implementation-to-
model correspondence rather than treating a tautological model as assurance.

The Agda model proves properties by construction. Real-world session
revocation, device attestation, key material secrecy, and origin authenticity
still require separate implementations, threat models, and trusted inputs.

Futhark traverses declared graph edges. Reachability is not proof of
unauthorized reachability. Dense adjacency costs O(n^2) memory.

AWK assumes trusted, sanitized TSV telemetry, ordered nondecreasing timestamps,
unique account identifiers, and a shared centralized stream. Its account
failure window persists until expiry; a real production gateway needs reliable
distributed counters, signed telemetry, event de-duplication, bounded storage,
and robust abuse/denial-of-service controls. `STEP_UP` is a decision to require
additional verification, not automatic access approval.

## Next integration boundary

Map C11 engine facts to immutable provenance IDs, generate canonical Alloy
instances, and require every claimed implementation finding to reference an
actual binary offset or authenticated event. No inference alone produces a
`PROVEN_VULNERABLE` or `PROVEN_COMPLIANT` verdict.
