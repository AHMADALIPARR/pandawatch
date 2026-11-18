#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
# Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
#
# Assembles the corpus with pw-xasm and checks that GNU objdump decodes the
# same instruction boundaries and mnemonics as the assembly decoder.
# usage: objdump_crosscheck.sh <pw-xasm> <corpus.s> <workdir>
set -eu
xasm=$1
corpus=$2
dir=$3
mkdir -p "$dir"
"$xasm" asm "$corpus" -o "$dir/corpus.bin"
"$xasm" disasm "$dir/corpus.bin" --listing > "$dir/pw.lst"
objdump -D -b binary -m i386:x86-64 -M intel "$dir/corpus.bin" |
  awk -F '\t' '/^ *[0-9a-f]+:\t/ && NF >= 3 {
    off = $1; sub(/^ */, "", off); sub(/:$/, "", off)
    split($3, w, " "); print off, w[1] }' > "$dir/objdump.lst"
diff -u "$dir/objdump.lst" "$dir/pw.lst"
echo "objdump agrees on $(wc -l < "$dir/pw.lst") instruction offsets and mnemonics"
