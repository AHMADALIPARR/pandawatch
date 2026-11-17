module pandawatch/Trust

// Bounded reference model: authorization, remote sessions, trust boundaries,
// PQC policy and buffer capacity. Designed for Alloy 6.
open util/ordering[Snapshot]

abstract sig Flag {}
one sig Yes, No extends Flag {}

sig Principal {}
sig Device {}
sig Resource {}
sig Route {}
sig Domain {}

sig Session {
  subject: one Principal,
  device: one Device,
  authenticated: one Flag,
  originBound: one Flag,
  active: one Flag,
  revoked: one Flag
}

sig Request {
  session: one Session,
  target: one Resource,
  route: one Route,
  sensitive: one Flag
}

sig Boundary {
  source: one Domain,
  destination: one Domain,
  protects: one Flag
}
sig Transition {
  via: one Boundary,
  authorized: one Flag,
  protectedEffect: one Flag
}

sig Artifact {
  byteLength: one Int,
  capacity: one Int
}
sig KeyRelease {
  measuredBoot: one Flag,
  userFactor: one Flag,
  requiresUserFactor: one Flag
}

sig CredentialFlow {
  reusableSecretSent: one Flag,
  approved: one Flag
}

sig CryptoUse {
  classicalOnly: one Flag,
  pqcRequired: one Flag
}

sig Snapshot {
  granted: Principal -> Resource,
  trustedDevices: set Device,
  blocked: set Session,
  reverified: set Session,
  admitted: set Request,
  transitions: set Transition,
  transmitted: set Artifact,
  approvedCrypto: set CryptoUse,
  keyReleases: set KeyRelease,
  credentialFlows: set CredentialFlow
}

pred GoodSession[st: Snapshot, s: Session] {
  s.authenticated = Yes
  s.originBound = Yes
  s.active = Yes
  s.revoked = No
  s.device in st.trustedDevices
  s not in st.blocked
}

pred CanAdmit[st: Snapshot, r: Request] {
  GoodSession[st, r.session]
  r.session.subject -> r.target in st.granted
}

// Deliberate model-level reference policy: every admitted operation is checked.
fact Enforcement {
  all st: Snapshot, r: st.admitted | CanAdmit[st, r]
  all st: Snapshot, t: st.transitions |
    (t.protectedEffect = Yes and t.via.protects = Yes) implies t.authorized = Yes
  all st: Snapshot, a: st.transmitted |
    a.byteLength >= 0 and a.capacity >= 0 and a.byteLength <= a.capacity
  all st: Snapshot, c: st.approvedCrypto |
    c.pqcRequired = Yes implies c.classicalOnly = No
  all st: Snapshot, k: st.keyReleases |
    k.measuredBoot = Yes and
      (k.requiresUserFactor = Yes implies k.userFactor = Yes)
  all st: Snapshot, f: st.credentialFlows |
    f.approved = Yes implies f.reusableSecretSent = No
}

// A blocked session may become unblocked only through explicit reverification.
fact TemporalRecovery {
  all st: Snapshot - last, s: st.blocked |
    s not in next[st].blocked implies s in next[st].reverified
}

assert AdmittedIsAuthorized {
  all st: Snapshot, r: st.admitted | CanAdmit[st, r]
}
assert NoProtectedBypass {
  all st: Snapshot, t: st.transitions |
    (t.protectedEffect = Yes and t.via.protects = Yes) implies t.authorized = Yes
}
assert NoOversizedArtifact {
  all st: Snapshot, a: st.transmitted | a.byteLength <= a.capacity
}
assert NoClassicalOnlyWhenPQCRequired {
  all st: Snapshot, c: st.approvedCrypto |
    c.pqcRequired = Yes implies c.classicalOnly = No
  all st: Snapshot, k: st.keyReleases |
    k.measuredBoot = Yes and
      (k.requiresUserFactor = Yes implies k.userFactor = Yes)
  all st: Snapshot, f: st.credentialFlows |
    f.approved = Yes implies f.reusableSecretSent = No
}
assert NoReusableSecretOnApprovedFlow {
  all st: Snapshot, f: st.credentialFlows |
    f.approved = Yes implies f.reusableSecretSent = No
}
assert KeyReleaseRequiresBoot {
  all st: Snapshot, k: st.keyReleases | k.measuredBoot = Yes
}
assert VerifiedUnblock {
  all st: Snapshot - last, s: st.blocked |
    s not in next[st].blocked implies s in next[st].reverified
}

// Witness of rejected activity; should be SAT in sufficiently large scope.
pred RejectedAttempt {
  some st: Snapshot, r: Request |
    r not in st.admitted and not CanAdmit[st, r]
}
// No routing-based authorization increase: path is not an input to CanAdmit.
pred ProxyIndependence {
  all st: Snapshot, r1, r2: Request |
    (r1.session = r2.session and r1.target = r2.target)
      implies (CanAdmit[st,r1] iff CanAdmit[st,r2])
}

check AdmittedIsAuthorized for 5 but 8 Int
check NoProtectedBypass for 5 but 8 Int
check NoOversizedArtifact for 5 but 8 Int
check NoClassicalOnlyWhenPQCRequired for 5 but 8 Int
check VerifiedUnblock for 5 but 8 Int
check NoReusableSecretOnApprovedFlow for 5 but 8 Int
check KeyReleaseRequiresBoot for 5 but 8 Int
run RejectedAttempt for 5 but 8 Int
run ProxyIndependence for 5 but 8 Int
