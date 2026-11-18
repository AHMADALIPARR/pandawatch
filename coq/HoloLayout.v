(*
 * CompCert Ctypes Reversal from wasm-holo/1.0
 * Root SHA-256: 3973ba88a4891b2df24eace5857ac8269fbdbd20145232d77a0eda0033843ab3
 *)
Require Import Coq.Lists.List.
Require Import Coq.ZArith.ZArith.
Require Import compcert.common.AST.
Require Import compcert.cfrontend.Ctypes.
Require Import compcert.lib.Integers.
Import ListNotations.
Open Scope Z_scope.

(* Identifier allocation for reversed Wasm Holo composites *)
Definition _holo_node : ident := 1%positive.
Definition _kind      : ident := 2%positive.
Definition _byte_size : ident := 3%positive.
Definition _children  : ident := 4%positive.

Definition holo_node_composite : composite_definition :=
  Composite _holo_node Struct
    (Member_plain _kind (Tint I32 Unsigned noattr) ::
     Member_plain _byte_size (Tint I32 Unsigned noattr) ::
     Member_plain _children (Tpointer (Tstruct _holo_node noattr) noattr) :: nil)
    noattr.

Definition _holo_c_AccountRecord : ident := 10%positive.
Definition _holo_c_AccountRecord_status : ident := 11%positive.
Definition _holo_c_AccountRecord_account_id : ident := 12%positive.
Definition _holo_c_AccountRecord_balance_cents : ident := 13%positive.
Definition _holo_c_AccountRecord_currency : ident := 14%positive.
Definition holo_c_AccountRecord_composite : composite_definition :=
  Composite _holo_c_AccountRecord Struct
    (Member_plain _holo_c_AccountRecord_status (Tint I8 Unsigned noattr) ::
     Member_plain _holo_c_AccountRecord_account_id (Tint I32 Unsigned noattr) ::
     Member_plain _holo_c_AccountRecord_balance_cents (Tlong Unsigned noattr) ::
     Member_plain _holo_c_AccountRecord_currency (Tint I32 Unsigned noattr) :: nil)
    noattr.

Record holo_c_AccountRecord_holo_witness : Prop := {
  holo_c_AccountRecord_expected_size  := 24;
  holo_c_AccountRecord_expected_align := 8
}.

Definition _holo_c_parts : ident := 15%positive.
Definition _holo_c_parts_raw_bits : ident := 16%positive.
Definition _holo_c_parts_amount : ident := 17%positive.
Definition _holo_c_parts_flags : ident := 18%positive.
Definition holo_c_parts_composite : composite_definition :=
  Composite _holo_c_parts Struct
    (Member_plain _holo_c_parts_raw_bits (Tlong Unsigned noattr) ::
     Member_plain _holo_c_parts_amount (Tint I32 Unsigned noattr) ::
     Member_plain _holo_c_parts_flags (Tint I16 Unsigned noattr) :: nil)
    noattr.

Record holo_c_parts_holo_witness : Prop := {
  holo_c_parts_expected_size  := 8;
  holo_c_parts_expected_align := 8
}.

Definition _holo_cobol_ACCOUNT_RECORD : ident := 19%positive.
Definition _holo_cobol_ACCOUNT_RECORD_ACCT_STATUS : ident := 20%positive.
Definition _holo_cobol_ACCOUNT_RECORD_ACCT_ID : ident := 21%positive.
Definition _holo_cobol_ACCOUNT_RECORD_ACCT_BALANCE : ident := 22%positive.
Definition _holo_cobol_ACCOUNT_RECORD_ACCT_CURRENCY : ident := 23%positive.
Definition _holo_cobol_ACCOUNT_RECORD_ACCT_FLAGS_RAW : ident := 24%positive.
Definition _holo_cobol_ACCOUNT_RECORD_ACCT_FLAGS_NUM : ident := 25%positive.
Definition _holo_cobol_ACCOUNT_RECORD_ACCT_HISTORY : ident := 26%positive.
Definition holo_cobol_ACCOUNT_RECORD_composite : composite_definition :=
  Composite _holo_cobol_ACCOUNT_RECORD Struct
    (Member_plain _holo_cobol_ACCOUNT_RECORD_ACCT_STATUS (Tint I8 Unsigned noattr) ::
     Member_plain _holo_cobol_ACCOUNT_RECORD_ACCT_ID (Tint I32 Unsigned noattr) ::
     Member_plain _holo_cobol_ACCOUNT_RECORD_ACCT_BALANCE (Tarray (Tint I8 Unsigned noattr) 7 noattr) ::
     Member_plain _holo_cobol_ACCOUNT_RECORD_ACCT_CURRENCY (Tarray (Tint I8 Unsigned noattr) 3 noattr) ::
     Member_plain _holo_cobol_ACCOUNT_RECORD_ACCT_FLAGS_RAW (Tint I32 Unsigned noattr) ::
     Member_plain _holo_cobol_ACCOUNT_RECORD_ACCT_FLAGS_NUM (Tint I16 Unsigned noattr) ::
     Member_plain _holo_cobol_ACCOUNT_RECORD_ACCT_HISTORY (Tarray (Tint I8 Unsigned noattr) 20 noattr) :: nil)
    noattr.

Record holo_cobol_ACCOUNT_RECORD_holo_witness : Prop := {
  holo_cobol_ACCOUNT_RECORD_expected_size  := 39;
  holo_cobol_ACCOUNT_RECORD_expected_align := 1
}.

Definition _holo_sqlite_account_record : ident := 27%positive.
Definition _holo_sqlite_account_record_account_id : ident := 28%positive.
Definition _holo_sqlite_account_record_status : ident := 29%positive.
Definition _holo_sqlite_account_record_balance_cents : ident := 30%positive.
Definition _holo_sqlite_account_record_currency : ident := 31%positive.
Definition holo_sqlite_account_record_composite : composite_definition :=
  Composite _holo_sqlite_account_record Struct
    (Member_plain _holo_sqlite_account_record_account_id (Tlong Unsigned noattr) ::
     Member_plain _holo_sqlite_account_record_status (Tarray (Tint I8 Unsigned noattr) 32 noattr) ::
     Member_plain _holo_sqlite_account_record_balance_cents (Tlong Unsigned noattr) ::
     Member_plain _holo_sqlite_account_record_currency (Tarray (Tint I8 Unsigned noattr) 32 noattr) :: nil)
    noattr.

Record holo_sqlite_account_record_holo_witness : Prop := {
  holo_sqlite_account_record_expected_size  := 80;
  holo_sqlite_account_record_expected_align := 1
}.

Definition _holo_sqlite_transactions : ident := 32%positive.
Definition _holo_sqlite_transactions_tx_id : ident := 33%positive.
Definition _holo_sqlite_transactions_account_id : ident := 34%positive.
Definition _holo_sqlite_transactions_delta_cents : ident := 35%positive.
Definition _holo_sqlite_transactions_created_at : ident := 36%positive.
Definition holo_sqlite_transactions_composite : composite_definition :=
  Composite _holo_sqlite_transactions Struct
    (Member_plain _holo_sqlite_transactions_tx_id (Tlong Unsigned noattr) ::
     Member_plain _holo_sqlite_transactions_account_id (Tlong Unsigned noattr) ::
     Member_plain _holo_sqlite_transactions_delta_cents (Tlong Unsigned noattr) ::
     Member_plain _holo_sqlite_transactions_created_at (Tarray (Tint I8 Unsigned noattr) 32 noattr) :: nil)
    noattr.

Record holo_sqlite_transactions_holo_witness : Prop := {
  holo_sqlite_transactions_expected_size  := 56;
  holo_sqlite_transactions_expected_align := 1
}.
