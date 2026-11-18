#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
# Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
#
# rblob end to end on the rust_ledger fixture crate: ingest (crate dir and
# the single lib.rs), verify, disassemble into functors, the committed blob
# digest, and rejection of a tampered blob.
# usage: rblob_cli.sh <rblob> <fixture-crate-dir> <expected-sha256> <workdir>
set -eu
rblob=$1
crate=$2
want=$3
dir=$4
mkdir -p "$dir"
"$rblob" ingest "$crate" -o "$dir/ledger.rblob" > "$dir/ingest.json"
cat "$dir/ingest.json"
grep -q "\"sha256\": \"$want\"" "$dir/ingest.json"
"$rblob" verify "$dir/ledger.rblob" > "$dir/verify.json"
grep -q '"verified": true' "$dir/verify.json"
"$rblob" disassemble "$dir/ledger.rblob" > "$dir/functors.json"
grep -q '"name": "Functor_AccountRecord"' "$dir/functors.json"
grep -q '"name": "Functor_rust_ledger_Module"' "$dir/functors.json"
grep -q '"lean_signature": "def F_AccountRecord : Type \\u2192 Type := fun _ => AccountRecord -- 2 morphisms, 16B @ align 8"' "$dir/functors.json"
"$rblob" ingest "$crate/src/lib.rs" -o "$dir/lib.rblob" > /dev/null
"$rblob" disassemble "$dir/lib.rblob" | grep -q '"crate": "lib"'
# Flip one payload byte: verification must fail with exit status 1.
size=$(wc -c < "$dir/ledger.rblob")
head -c 60 "$dir/ledger.rblob" > "$dir/bad.rblob"
printf 'X' >> "$dir/bad.rblob"
tail -c $((size - 61)) "$dir/ledger.rblob" >> "$dir/bad.rblob"
if "$rblob" verify "$dir/bad.rblob" 2> "$dir/bad.err"; then echo "tampered blob verified"; exit 1; fi
grep -q 'SHA-256 verification failed' "$dir/bad.err"
echo "rblob: ingest, verify, disassemble, digest and tamper check passed"
