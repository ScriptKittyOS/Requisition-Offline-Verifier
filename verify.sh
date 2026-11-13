#!/bin/sh
# Verifies the signed statement and the signed decision in record/. Offline: opens no network connection.
# Usage: sh verify.sh        Exit status 0 only if both records pass.
set -u
cd "$(dirname "$0")" || exit 2
status=0
for record in statement decision; do
  echo "######## record/$record.json"
  python3 -I verifier/verify_offline.py \
    --arguments record/arguments.json --act-type payments.refund_send \
    --record "record/$record.json" --registry record/public-keys.json \
    --lab-verify verifier/lab-verify \
    --accept-signer kms --require-pq || status=1
  echo
done
if [ "$status" -eq 0 ]; then echo "RESULT: PASS (both records verify)"; else echo "RESULT: FAIL (at least one record did not verify)"; fi
exit "$status"
