-
  HoloDSL.lean — Custom Lean 4 DSL piping Rust & Wasm (wa) macros into Lean Lemmas
  Source: wasm-holo/1.0 | Root SHA-256: 3973ba88a4891b2df24eace5857ac8269fbdbd20145232d77a0eda0033843ab3
-/
import Lean

namespace HoloDSL

structure FieldSpec where
  name   : String
  offset : Nat
  size   : Nat
  align  : Nat
  deriving Repr, BEq

structure HoloRecord where
  name      : String
  totalSize : Nat
  align     : Nat
  fields    : List FieldSpec
  deriving Repr

def FieldSpec.within (f : FieldSpec) (limit : Nat) : Prop :=
  f.offset + f.size <= limit

def HoloRecord.allWithin (r : HoloRecord) : Prop :=
  ∀ f ∈ r.fields, f.within r.totalSize

def HoloRecord.aligned (r : HoloRecord) : Prop :=
  r.align > 0 ∧ r.totalSize % r.align = 0

-- ==========================================================================
-- Custom Lean 4 Macro DSL: Rust ABI (`rust_struct!`) + Wasm (`wa_holo!`)
-- ==========================================================================

declare_syntax_cat holoField
syntax ident ":" ident "@" num ":" num "align" num : holoField

-- Pipe Rust-style struct macro into a Lean HoloRecord
syntax "rust_struct!" ident "{" holoField,* "}" "size" num "align" num : command

macro_rules
  | `(rust_struct! $name:ident { $[$f:ident : $_ty:ident @ $off:num : $sz:num align $al:num],* } size $tot:num align $ral:num) =>
    `(def $name : HoloRecord :=
        { name := $(Lean.quote name.getId.toString),
          totalSize := $tot,
          align := $ral,
          fields := [ $[{ name := $(Lean.quote f.getId.toString), offset := $off, size := $sz, align := $al }],* ] })

-- Pipe Wasm Holo (`wa_holo!`) layer witness directly into Lean 4 lemmas
syntax "wa_holo!" ident "(" str ")" "=>" ident : command

macro_rules
  | `(wa_holo! $thmName:ident ( $_sec:str ) => $recName:ident) =>
    `(lemma $thmName : $recName.allWithin ∧ $recName.aligned := by
        constructor
        · intro f hf
          simp [$recName, FieldSpec.within] at hf ⊢
          rcases hf with h | h <;> try omega
        · simp [$recName, HoloRecord.aligned])

-- ==========================================================================
-- Reversed Wasm Holo Records & Auto-Generated Lemmas
-- ==========================================================================

rust_struct! c_AccountRecord { status : u8 @ 0 : 1 align 1, account_id : u8 @ 4 : 4 align 4, balance_cents : u8 @ 8 : 8 align 8, currency : u8 @ 16 : 4 align 1 } size 24 align 8
wa_holo! c_AccountRecord_sound ("holo.layouts") => c_AccountRecord

rust_struct! c_parts { raw_bits : u8 @ 0 : 8 align 8, amount : u8 @ 0 : 4 align 4, flags : u8 @ 0 : 2 align 2 } size 8 align 8
wa_holo! c_parts_sound ("holo.layouts") => c_parts

rust_struct! cobol_ACCOUNT_RECORD { ACCT_STATUS : u8 @ 0 : 1 align 1, ACCT_ID : u8 @ 1 : 4 align 1, ACCT_BALANCE : u8 @ 5 : 7 align 1, ACCT_CURRENCY : u8 @ 12 : 3 align 1, ACCT_FLAGS_RAW : u8 @ 15 : 4 align 1, ACCT_FLAGS_NUM : u8 @ 15 : 2 align 1, ACCT_HISTORY : u8 @ 19 : 20 align 1 } size 39 align 1
wa_holo! cobol_ACCOUNT_RECORD_sound ("holo.layouts") => cobol_ACCOUNT_RECORD

rust_struct! sqlite_account_record { account_id : u8 @ 0 : 8 align 1, status : u8 @ 8 : 32 align 1, balance_cents : u8 @ 40 : 8 align 1, currency : u8 @ 48 : 32 align 1 } size 80 align 1
wa_holo! sqlite_account_record_sound ("holo.layouts") => sqlite_account_record

rust_struct! sqlite_transactions { tx_id : u8 @ 0 : 8 align 1, account_id : u8 @ 8 : 8 align 1, delta_cents : u8 @ 16 : 8 align 1, created_at : u8 @ 24 : 32 align 1 } size 56 align 1
wa_holo! sqlite_transactions_sound ("holo.layouts") => sqlite_transactions

end HoloDSL(*
def FieldSpec.disjoint (a b : FieldSpec) : Prop :=
  a.offset + a.size ≤ b.offset ∨ b.offset + b.size ≤ a.offset

-- Decidable instance so `decide` discharges pairwise checks in kernel reduction
instance (a b : FieldSpec) : Decidable (FieldSpec.disjoint a b) :=
  inferInstanceAs (Decidable (a.offset + a.size ≤ b.offset ∨ b.offset + b.size ≤ a.offset))

def HoloRecord.pairwiseDisjoint : List FieldSpec → Prop
  | [] => True
  | f :: fs => (∀ g ∈ fs, FieldSpec.disjoint f g) ∧ HoloRecord.pairwiseDisjoint fs

instance : DecidablePred HoloRecord.pairwiseDisjoint
  | [] => isTrue trivial
  | f :: fs =>
    haveI : DecidablePred HoloRecord.pairwiseDisjoint := inferInstance
    inferInstanceAs (Decidable ((∀ g ∈ fs, FieldSpec.disjoint f g) ∧ HoloRecord.pairwiseDisjoint fs))

def HoloRecord.nonOverlapping (r : HoloRecord) : Prop :=
  HoloRecord.pairwiseDisjoint r.fields
macro_rules
  | `(wa_holo! $thmName:ident ( $_sec:str ) => $recName:ident) =>
    `(lemma $thmName : $recName.allWithin ∧ $recName.aligned ∧ $recName.nonOverlapping := by
        refine ⟨?_, ?_, ?_⟩
        · intro f hf
          simp [$recName, FieldSpec.within] at hf
          rcases hf with h | h <;> try omega
        · simp [$recName, HoloRecord.aligned]
        · simp only [$recName, HoloRecord.nonOverlapping]
          decide)
def HoloRecord.contiguousFrom : Nat → List FieldSpec → Prop
  | expectedOffset, [] => expectedOffset = 0 -- only used if empty; see wrapper below
  | expectedOffset, [f] => f.offset = expectedOffset
  | expectedOffset, f :: g :: fs =>
      f.offset = expectedOffset ∧
      HoloRecord.contiguousFrom (f.offset + f.size) (g :: fs)

-- Cleaner tail-checking version that also locks totalSize with zero trailing padding:
def HoloRecord.tightlyPackedFrom : Nat → Nat → List FieldSpec → Prop
  | cursor, total, [] => cursor = total
  | cursor, total, f :: fs =>
      f.offset = cursor ∧
      HoloRecord.tightlyPackedFrom (f.offset + f.size) total fs

instance (cursor total : Nat) : DecidablePred (HoloRecord.tightlyPackedFrom cursor total)
  | [] => inferInstanceAs (Decidable (cursor = total))
  | f :: fs =>
      haveI : DecidablePred (HoloRecord.tightlyPackedFrom (f.offset + f.size) total) := inferInstance
      inferInstanceAs (Decidable (f.offset = cursor ∧ HoloRecord.tightlyPackedFrom (f.offset + f.size) total fs))

def HoloRecord.contiguous (r : HoloRecord) : Prop :=
  HoloRecord.tightlyPackedFrom 0 r.totalSize r.fields

instance (r : HoloRecord) : Decidable r.contiguous :=
  inferInstanceAs (Decidable (HoloRecord.tightlyPackedFrom 0 r.totalSize r.fields))
syntax "wa_holo!" ("packed")? ident "(" str ")" "=>" ident : command

macro_rules
  -- Standard ABI witness (allows alignment padding, forbids overlap/overflow)
  | `(wa_holo! $thmName:ident ( $_sec:str ) => $recName:ident) =>
    `(lemma $thmName : $recName.allWithin ∧ $recName.aligned ∧ $recName.nonOverlapping := by
        refine ⟨?_, ?_, ?_⟩
        · intro f hf
          simp [$recName, FieldSpec.within] at hf
          rcases hf with h | h <;> try omega
        · simp [$recName, HoloRecord.aligned]
        · simp only [$recName, HoloRecord.nonOverlapping]
          decide)

  -- Strict zero-padding witness (enforces contiguous packing from byte 0 to totalSize)
  | `(wa_holo! packed $thmName:ident ( $_sec:str ) => $recName:ident) =>
    `(lemma $thmName : $recName.allWithin ∧ $recName.aligned ∧ $recName.nonOverlapping ∧ $recName.contiguous := by
        refine ⟨?_, ?_, ?_, ?_⟩
        · intro f hf
          simp [$recName, FieldSpec.within] at hf
          rcases hf with h | h <;> try omega
        · simp [$recName, HoloRecord.aligned]
        · simp only [$recName, HoloRecord.nonOverlapping]
          decide
        · simp only [$recName, HoloRecord.contiguous]
          decide)
Examples
 -- Padded C/Rust ABI layout (passes standard wa_holo!, fails `packed` due to 3-byte pad after `status`)
rust_struct! c_AccountRecord {
  status : u8 @ 0 : 1 align 1,
  account_id : u32 @ 4 : 4 align 4,
  balance_cents : u64 @ 8 : 8 align 8,
  currency : u32 @ 16 : 4 align 1
} size 24 align 8
wa_holo! c_AccountRecord_sound ("holo.layouts") => c_AccountRecord

-- Zero-pad wire/Wasm frame (proves zero hidden gaps between fields)
rust_struct! uor_WireHeader {
  magic : u32 @ 0 : 4 align 1,
  version : u16 @ 4 : 2 align 1,
  flags : u16 @ 6 : 2 align 1,
  payload_len : u64 @ 8 : 8 align 1
} size 16 align 1
wa_holo! packed uor_WireHeader_packed ("holo.layouts") => uor_WireHeader
