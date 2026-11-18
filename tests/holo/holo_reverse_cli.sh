#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
# Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
#
# holo-reverse end to end: bsm packs the C, COBOL, SQL and assembly fixtures,
# holo-reverse writes holo_reversed_c23.h, holo_compcert.v and HoloDSL.lean
# (digests equal to the reference reverse-compiler's files), the header
# compiles as C11, --lean-import emits the records against an imported DSL,
# and a module with a tampered layer is refused.
# usage: holo_reverse_cli.sh <holo-reverse> <bsm> <fixtures-dir> <workdir> <cc>
#                            <sha256-h> <sha256-v> <sha256-lean>
set -eu
hr=$1
bsm=$2
fx=$3
dir=$4
cc=$5
want_h=$6
want_v=$7
want_lean=$8
mkdir -p "$dir"

sha() { sha256sum "$1" | cut -d' ' -f1; }

"$bsm" pack "$fx/account.h" "$fx/account.cpy" "$fx/ledger.sql" "$fx/ledger.s" -o "$dir/ledger.holo.wasm" > /dev/null
"$hr" "$dir/ledger.holo.wasm" --out-dir "$dir/out" | tee "$dir/generated.txt"
grep -q '^Generated:$' "$dir/generated.txt"
test "$(sha "$dir/out/holo_reversed_c23.h")" = "$want_h"
test "$(sha "$dir/out/holo_compcert.v")" = "$want_v"
test "$(sha "$dir/out/HoloDSL.lean")" = "$want_lean"

"$cc" -std=c11 -Wall -Wextra -Werror -fsyntax-only -include "$dir/out/holo_reversed_c23.h" -x c /dev/null

"$hr" "$dir/ledger.holo.wasm" --out-dir "$dir/lean" --lean-import HoloDSL.HoloDSL_checked > /dev/null
grep -q '^import HoloDSL.HoloDSL_checked$' "$dir/lean/HoloDSL.lean"
grep -q '^wa_holo! c_AccountRecord_sound ("holo.layouts") => c_AccountRecord$' "$dir/lean/HoloDSL.lean"
grep -q '^theorem cobol_ACCOUNT_RECORD_sound : HoloRecord.allWithin cobol_ACCOUNT_RECORD' "$dir/lean/HoloDSL.lean"
test "$(tail -n 1 "$dir/lean/HoloDSL.lean")" = "end HoloReversed"

LC_ALL=C sed 's/audit_log/audit_lof/g' "$dir/ledger.holo.wasm" > "$dir/tampered.holo.wasm"
set +e
"$hr" "$dir/tampered.holo.wasm" --out-dir "$dir/tampered" 2> "$dir/err.txt"; rc=$?
set -e
test $rc -eq 1
grep -q 'RuntimeError: Wasm Holo SHA-256 integrity verification failed!' "$dir/err.txt"
echo "holo-reverse CLI checks passed"
