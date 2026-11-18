/-
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
  Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
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

open Lean in
macro_rules
  | `(rust_struct! $name:ident { $fs:holoField,* } size $tot:num align $ral:num) => do
    let specs ← fs.getElems.mapM fun fld => match fld with
      | `(holoField| $f:ident : $_ty:ident @ $off:num : $sz:num align $al:num) =>
        `(FieldSpec.mk $(quote f.getId.toString) $off $sz $al)
      | _ => Macro.throwUnsupported
    -- `size` and `align` are DSL keywords from here on, so the record is
    -- built with the positional constructors.
    `(def $name : HoloRecord :=
        HoloRecord.mk $(quote name.getId.toString) $tot $ral [ $specs,* ])

instance (f : FieldSpec) (limit : Nat) : Decidable (f.within limit) :=
  inferInstanceAs (Decidable (f.offset + f.size <= limit))

instance (r : HoloRecord) : Decidable r.allWithin :=
  inferInstanceAs (Decidable (∀ f ∈ r.fields, f.within r.totalSize))

instance (r : HoloRecord) : Decidable r.aligned :=
  inferInstanceAs (Decidable (r.align > 0 ∧ r.totalSize % r.align = 0))

-- Pipe Wasm Holo (`wa_holo!`) layer witness directly into Lean 4 theorems
syntax "wa_holo!" ident "(" str ")" "=>" ident : command

macro_rules
  | `(wa_holo! $thmName:ident ( $_sec:str ) => $recName:ident) =>
    `(theorem $thmName : HoloRecord.allWithin $recName ∧ HoloRecord.aligned $recName := by
        decide)

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

end HoloDSL
