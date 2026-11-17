# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
# Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
#
# Reads the text summary printed by `java -jar org.alloytools.alloy.dist.jar
# exec -t text Trust.als` (lines such as "00. check Name   0   UNSAT") and
# fails unless every `check` is UNSAT (no counterexample within scope), every
# `run` is SAT (an instance exists), and exactly `-v expected=N` commands ran.
/^[0-9]+\. +(check|run) / {
  kind = $2; name = $3; res = $NF; n++
  if (kind == "check" && res != "UNSAT") { bad++; print "FAIL check " name ": " res " (counterexample found)"; next }
  if (kind == "run" && res != "SAT") { bad++; print "FAIL run " name ": " res " (no instance)"; next }
  print "ok   " kind " " name " " res
}
END {
  if (expected + 0 > 0 && n != expected + 0) { print "FAIL expected " expected " commands, saw " n; exit 1 }
  if (n == 0) { print "FAIL no Alloy command results parsed"; exit 1 }
  if (bad) exit 1
  print n " Alloy commands matched expectations"
}
