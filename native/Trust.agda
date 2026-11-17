{-# OPTIONS --safe --without-K #-}
module Trust where

open import Agda.Builtin.Bool using (Bool; true; false)
open import Agda.Builtin.Equality using (_≡_; refl)
open import Agda.Builtin.Maybe using (Maybe; just; nothing)

record Facts : Set where
  constructor facts
  field
    authenticated : Bool
    originBound   : Bool
    active        : Bool
    revoked       : Bool
    deviceTrusted : Bool
    grant         : Bool
open Facts public

-- A proof-carrying grant cannot be formed without all six evidence fields.
data Admitted (f : Facts) : Set where
  grantAccess : authenticated f ≡ true
             → originBound f ≡ true
             → active f ≡ true
             → revoked f ≡ false
             → deviceTrusted f ≡ true
             → grant f ≡ true
             → Admitted f

checkTrue : (b : Bool) → Maybe (b ≡ true)
checkTrue true  = just refl
checkTrue false = nothing

checkFalse : (b : Bool) → Maybe (b ≡ false)
checkFalse true  = nothing
checkFalse false = just refl

admit : (f : Facts) → Maybe (Admitted f)
admit f with checkTrue (authenticated f) | checkTrue (originBound f) | checkTrue (active f) | checkFalse (revoked f) | checkTrue (deviceTrusted f) | checkTrue (grant f)
... | just pa | just po | just pt | just pr | just pd | just pg = just (grantAccess pa po pt pr pd pg)
... | _       | _       | _       | _       | _       | _       = nothing

admitted-authenticated : {f : Facts} → Admitted f → authenticated f ≡ true
admitted-authenticated (grantAccess pa po pt pr pd pg) = pa

admitted-not-revoked : {f : Facts} → Admitted f → revoked f ≡ false
admitted-not-revoked (grantAccess pa po pt pr pd pg) = pr

admitted-granted : {f : Facts} → Admitted f → grant f ≡ true
admitted-granted (grantAccess pa po pt pr pd pg) = pg

-- The transport route is deliberately excluded from authority facts.
data Transport : Set where
  direct socks onion : Transport

authorize : (f : Facts) → Transport → Maybe (Admitted f)
authorize f route = admit f

route-independent : (f : Facts) (p q : Transport) → authorize f p ≡ authorize f q
route-independent f p q = refl

-- A blocked session never receives access without new validated facts:
-- its prior authorization object is not accepted as proof of current facts.
