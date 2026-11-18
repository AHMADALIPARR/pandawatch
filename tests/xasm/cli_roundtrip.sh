#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
# Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
#
# pw-xasm end to end: asm -> disasm -> asm gives identical bytes, then
# lift -> pw-xray-verify, and the Fortran struct dump of the lifted bundle.
# usage: cli_roundtrip.sh <pw-xasm> <pw-xray-verify> <corpus.s> <workdir>
set -eu
xasm=$1
verify=$2
corpus=$3
dir=$4
mkdir -p "$dir"
"$xasm" asm "$corpus" -o "$dir/a.bin" --base 0x401000
"$xasm" disasm "$dir/a.bin" --base 0x401000 > "$dir/a.dis"
"$xasm" asm "$dir/a.dis" -o "$dir/b.bin" --base 0x401000
cmp "$dir/a.bin" "$dir/b.bin"
echo "round trip: $(wc -l < "$dir/a.dis") instructions, bytes identical"
"$xasm" lift "$dir/a.bin" -o "$dir/a.pwxray" --base 0x401000
"$verify" "$dir/a.pwxray" --binary "$dir/a.bin"
"$xasm" structs "$dir/a.pwxray" > "$dir/a.structs"
grep -q '^padding: all zero$' "$dir/a.structs"
grep -q 'verdicts: compliant 0, vulnerable 0, unknown 4, invalid 0' "$dir/a.structs"
echo "structs: Fortran parse of the lifted bundle has zero padding"
