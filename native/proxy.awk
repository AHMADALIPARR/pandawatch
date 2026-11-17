# POSIX AWK. Input: tab-separated, no header; ordered by nondecreasing epoch.
# epoch account device route session auth_ok device_ok grant_ok revoked
# All flags must be 0 or 1. Aggregate failures by ACCOUNT, not by source IP.
# Output: epoch<TAB>account<TAB>session<TAB>ALLOW|DENY|STEP_UP<TAB>reason
# -v window=600 -v limit=5. No packet interception or active network access.
BEGIN { FS = OFS = "\t"; window += 0; limit += 0;
  if (window <= 0) window = 600;
  if (limit <= 0) limit = 5;
  print "epoch", "account", "session", "decision", "reason";
}
function flag(x) { return x == "0" || x == "1" }
function fail(epoch, account, session, reason) {
  print epoch, account, session, "DENY", reason
}
function expire(account, t,    head, tail, key) {
  head = first[account] + 0; tail = last[account] + 0;
  while (head < tail) {
    key = account SUBSEP head;
    if (t - failures[key] < window) break;
    delete failures[key]; head++;
  }
  first[account] = head
}
{
  if (NF != 9 || $1 !~ /^[0-9]+$/ || $2 == "" || $3 == "" || $5 == "" ||
      !flag($6) || !flag($7) || !flag($8) || !flag($9)) {
    fail($1, $2, $5, "INVALID_INPUT"); next
  }
  epoch = $1 + 0; account = $2; session = $5;
  if (NR > 1 && epoch < previous_epoch) {
    fail($1, account, session, "OUT_OF_ORDER"); next
  }
  previous_epoch = epoch;
  expire(account, epoch);
  if ($9 == "1") {
    fail($1, account, session, "REVOKED"); next
  }
  if ($6 == "0" || $7 == "0" || $8 == "0") {
    slot = last[account] + 0;
    failures[account SUBSEP slot] = epoch;
    last[account] = slot + 1;
    fail($1, account, session, "AUTH_OR_POLICY_FAILED"); next
  }
  if ((last[account] + 0) - (first[account] + 0) >= limit) {
    print $1, account, session, "STEP_UP", "ACCOUNT_FAILURE_WINDOW"; next
  }
  print $1, account, session, "ALLOW", "VERIFIED"
}
