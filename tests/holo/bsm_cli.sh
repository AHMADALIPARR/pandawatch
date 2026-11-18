#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
# Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
#
# bsm end to end on tests/fixtures/bsm: the C header, COBOL copybook, SQL DDL
# and assembly sample packed for both ABIs (digests equal to the reference
# packer's modules), inspect in text and JSON form, the rust_ledger crate,
# a SQLite database and an x86-64 ELF when the tools to build them are given,
# and the argparse-style usage errors.
# usage: bsm_cli.sh <bsm> <fixtures-dir> <rust-crate-dir> <workdir>
#                   <sha256-lp64> <sha256-wasm32> [<cc-for-elf|-> [<sqlite3|->]]
set -eu
bsm=$1
fx=$2
crate=$3
dir=$4
want_lp64=$5
want_wasm32=$6
cc=${7:--}
sqlite=${8:--}
mkdir -p "$dir"

sha() { sha256sum "$1" | cut -d' ' -f1; }

"$bsm" pack "$fx/account.h" "$fx/account.cpy" "$fx/ledger.sql" "$fx/ledger.s" -o "$dir/ledger.holo.wasm" > "$dir/pack.json"
cat "$dir/pack.json"
test "$(sha "$dir/ledger.holo.wasm")" = "$want_lp64"
"$bsm" pack "$fx/account.h" "$fx/account.cpy" "$fx/ledger.sql" "$fx/ledger.s" --abi wasm32 -o "$dir/ledger32.holo.wasm" > /dev/null
test "$(sha "$dir/ledger32.holo.wasm")" = "$want_wasm32"

"$bsm" inspect "$dir/ledger.holo.wasm" | tee "$dir/inspect.txt"
grep -q '^Integrity Verified: True$' "$dir/inspect.txt"
grep -q "^Stats: {'records': 6, 'cfgs': 2, 'symbols': 10, 'cross_links': 2}$" "$dir/inspect.txt"
grep -q "^Layers: \['holo.types', 'holo.layouts', 'holo.cfg', 'holo.symbols'\]$" "$dir/inspect.txt"
"$bsm" inspect "$dir/ledger.holo.wasm" --json > "$dir/inspect.json"
grep -q '"integrity_verified": true' "$dir/inspect.json"
grep -q '"name": "ACCOUNT-RECORD"' "$dir/inspect.json"
grep -q '"name": "account_record"' "$dir/inspect.json"

"$bsm" pack "$crate" -o "$dir/rust.holo.wasm" > /dev/null
"$bsm" inspect "$dir/rust.holo.wasm" > "$dir/rust.txt"
grep -q "'functors': 2" "$dir/rust.txt"
grep -q "'holo.functors'" "$dir/rust.txt"

if [ "$sqlite" != - ]; then
    rm -f "$dir/ledger.db"
    "$sqlite" "$dir/ledger.db" < "$fx/ledger.sql"
    "$bsm" pack "$dir/ledger.db" -o "$dir/db.holo.wasm" > /dev/null
    "$bsm" inspect "$dir/db.holo.wasm" | grep -q "'records': 2"
fi

if [ "$cc" != - ]; then
    "$cc" -nostdlib -static -no-pie -o "$dir/ledger.elf" "$fx/ledger_elf.S"
    "$bsm" pack "$dir/ledger.elf" -o "$dir/elf.holo.wasm" > /dev/null
    "$bsm" inspect "$dir/elf.holo.wasm" --json > "$dir/elf.json"
    grep -q '"machine": "x86-64"' "$dir/elf.json"
    grep -q '"cfgs": 3' "$dir/elf.json"
    grep -A1 '"calls": \[' "$dir/elf.json" | grep -q '"ledger_sum"'
fi

# Usage errors exit with status 2.
set +e
"$bsm" pack "$fx/account.h" 2> "$dir/err.txt"; rc=$?
set -e
test $rc -eq 2
grep -q 'error: the following arguments are required: -o/--output' "$dir/err.txt"
echo "bsm CLI checks passed"
