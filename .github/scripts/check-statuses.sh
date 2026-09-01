#!/usr/bin/env bash
# Reject any CheckResult/ScanResult Status value outside the recognised set.
#
# The Status field is a plain string. Three separate scoring defects came from
# that: MANUAL, then WARN, then ERROR each ended up in the compliance score's
# denominator as an automated check that could never pass. The report generators
# now only score PASS and FAIL, but a stray status is still a bug worth catching
# at the point it is written rather than after it reaches a customer report.
#
# Run locally with: .github/scripts/check-statuses.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VALID="PASS FAIL INFO MANUAL ERROR"
fails=0

# Both forms: a struct field `Status: "X"` and an assignment `base.Status = "X"`.
# The assignment form was missed originally, and it is what the newer modules use.
while IFS= read -r line; do
  [ -z "$line" ] && continue
  file="${line%%:*}"
  rest="${line#*:}"
  lineno="${rest%%:*}"
  value="$(echo "$line" | sed -E 's/.*(Status:|\.Status[[:space:]]*=)[[:space:]]*"([^"]*)".*/\2/')"
  ok=0
  for v in $VALID; do [ "$value" = "$v" ] && ok=1 && break; done
  if [ "$ok" -eq 0 ]; then
    echo "  INVALID  ${file#$ROOT/}:${lineno}  Status: \"${value}\""
    fails=$((fails + 1))
  fi
done < <(grep -rnE '(Status:|\.Status[[:space:]]*=)[[:space:]]*"[^"]*"' --include='*.go' "$ROOT/scanner" 2>/dev/null)

if [ "$fails" -gt 0 ]; then
  echo
  echo "FAILED: $fails status value(s) outside the recognised set."
  echo "Valid: $VALID (see StatusPass..StatusError in pkg/*/checks/types.go)"
  exit 1
fi

echo "All Status values are recognised."
