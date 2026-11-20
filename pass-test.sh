#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
# What a pass says, checked on the two signed records in record/. A pass prints one fixed sentence after its verdict:
# it shows the bytes were signed under the key supplied, and it is not permission to act. The deadline a record signs
# (a decision's, and a statement's, each in its own words) is reported
# as what the record says; it is compared with a time only when one is given (--at), and the exit status is the same
# whether that time is inside the record's window or years after it. The same record given twice gets the same answer.
# An argument a verifier does not take is a usage error, never skipped.
# Offline. Leaves this folder untouched; the one changed copy is made in a temporary directory removed at the end.
# Usage: sh pass-test.sh        Exit status 0 only if every case is as expected.
set -u
here=$(cd "$(dirname "$0")" && pwd) || exit 2
work=$(mktemp -d) || exit 2
trap 'rm -r "$work"' EXIT
bad=0
sentence='A pass shows these bytes were signed under the key you supplied. It is not permission to act. Whether an action may run is decided by the issuing system when it runs.'

verify() {  # $1 = folder holding record/ and verifier/, $2 = record name, the rest = further flags
  folder=$1; record=$2; shift 2
  python3 -I "$folder/verifier/verify_offline.py" \
    --arguments "$folder/record/arguments.json" --act-type payments.refund_send \
    --record "$folder/record/$record.json" --registry "$folder/record/public-keys.json" \
    --lab-verify "$folder/verifier/lab-verify" \
    --accept-signer kms --require-pq "$@"
}

after_sentence() {  # the lines that follow the line that is exactly the sentence; "NO SENTENCE" when no line is
  awk -v s="$sentence" 'found { print } $0 == s { found = 1 } END { if (!found) print "NO SENTENCE" }' "$1"
}

echoed() {  # the same lines in lab-verify's own answer, which verify_offline.py prints unchanged behind "  | "
  awk -v s="  | $sentence" 'found && !/^  \|/ { exit } found && /^  \| ./ && !/^  \| verdict_code: / { print substr($0, 5) }
    $0 == s { found = 1 } END { if (!found) print "NO SENTENCE" }' "$1"
}

run_case() {  # $1 = name, $2 = record, $3 = expected exit status, $4 = expected lines after the sentence, the rest = flags
  name=$1; record=$2; want_status=$3; want_lines=$4; shift 4
  verify "$here" "$record" "$@" > "$work/output.txt" 2>&1; got_status=$?
  got_lines=$(after_sentence "$work/output.txt")
  # on a pass lab-verify's own answer must end with the same lines: the time given reached it and it compared the same
  if [ "$want_status" = 0 ]; then got_echo=$(echoed "$work/output.txt"); else got_echo=$want_lines; fi
  if [ "$got_status" = "$want_status" ] && [ "$got_lines" = "$want_lines" ] && [ "$got_echo" = "$want_lines" ]; then echo "ok          $name"
  else echo "UNEXPECTED  $name -> exit $got_status (expected $want_status), after the sentence:"; echo "$got_lines"
    echo "and after the sentence in lab-verify's own answer:"; echo "$got_echo"; bad=1; fi
}

until='This decision allowed execution until 2026-11-13T15:57:48Z.'
run_case "the decision, no time given: its signed deadline is reported and nothing is compared" decision 0 "$until
No time was compared."
run_case "one second before the decision was made: closed, and still a pass" decision 0 "$until
At 2026-11-13T15:56:47Z the window was closed (it opened at 2026-11-13T15:56:48Z)." --at 2026-11-13T15:56:47Z
run_case "at the instant the decision was made: open" decision 0 "$until
At 2026-11-13T15:56:48Z the window was open (from 2026-11-13T15:56:48Z, until 2026-11-13T15:57:48Z)." --at 2026-11-13T15:56:48Z
run_case "one second before the deadline: open" decision 0 "$until
At 2026-11-13T15:57:47Z the window was open (from 2026-11-13T15:56:48Z, until 2026-11-13T15:57:48Z)." --at 2026-11-13T15:57:47Z
run_case "at the deadline: closed, and still a pass" decision 0 "$until
At 2026-11-13T15:57:48Z the window was closed (it ended at 2026-11-13T15:57:48Z)." --at 2026-11-13T15:57:48Z
run_case "years after the deadline: an expired decision is still a valid record" decision 0 "$until
At 2030-01-01T00:00:00Z the window was closed (it ended at 2026-11-13T15:57:48Z)." --at 2030-01-01T00:00:00Z
run_case "the statement, no time given: its signed exp is reported" statement 0 "This statement was valid until 2026-11-13T16:01:38Z.
No time was compared."
run_case "the statement at its exp: closed, and still a pass" statement 0 "This statement was valid until 2026-11-13T16:01:38Z.
At 2026-11-13T16:01:38Z the window was closed (it ended at 2026-11-13T16:01:38Z)." --at 2026-11-13T16:01:38Z
run_case "a time with an offset is a usage error, and nothing passes" decision 2 "NO SENTENCE" --at 2026-11-13T15:57:48+00:00
run_case "30 February is a usage error, and nothing passes" decision 2 "NO SENTENCE" --at 2026-02-30T00:00:00Z
run_case "a flag one letter longer than --at is a usage error: no argument is skipped" decision 2 "NO SENTENCE" --att 2026-11-13T15:57:00Z
run_case "a value with no flag before it is a usage error, and nothing passes" decision 2 "NO SENTENCE" 2026-11-13T15:57:00Z

# The receipt verifier alone, on the decision's Ed25519 envelope: it passes, and an argument it does not take is a
# usage error. A verifier that skipped "--att TIME" would pass and compare nothing, in silence.
python3 -I -c 'import json, sys
json.dump(json.load(open(sys.argv[1]))["decision"], open(sys.argv[2], "w"))' "$here/record/decision.json" "$work/envelope.json" || exit 2
receipt() { python3 -I "$here/verifier/verify_receipt.py" --receipt "$work/envelope.json" --registry "$here/record/public-keys.json" "$@"; }
receipt > "$work/output.txt" 2>&1; plain=$?
receipt --att 2026-11-13T15:57:00Z > "$work/unknown.txt" 2>&1; unknown=$?
if [ "$plain" = 0 ] && grep -q -x -F "$sentence" "$work/output.txt" && [ "$unknown" = 2 ] && ! grep -q -x -F "$sentence" "$work/unknown.txt"
then echo "ok          verify_receipt.py alone: a pass, and with an argument it does not take a usage error and no pass"
else echo "UNEXPECTED  verify_receipt.py alone -> exit $plain, and with an argument it does not take exit $unknown (expected 0 and 2)"; bad=1; fi

# Replay protection is not the verifier's: the same valid decision record presented twice gives the same pass, the
# same lines and the same exit status.
verify "$here" decision > "$work/first.txt" 2>&1; first=$?
verify "$here" decision > "$work/second.txt" 2>&1; second=$?
if [ "$first" = 0 ] && [ "$second" = 0 ] && cmp -s "$work/first.txt" "$work/second.txt" && grep -q -x -F "$sentence" "$work/first.txt"
then echo "ok          the same decision presented twice: the same pass, the same lines, the same exit status"
else echo "UNEXPECTED  the same decision presented twice -> exit $first, then $second"; bad=1; fi

# A record that does not verify prints no line that is the sentence.
mkdir "$work/changed" && cp -R "$here/record" "$here/verifier" "$work/changed/" || exit 2
(cd "$work/changed" && python3 -I -c 'import json
r = json.load(open("record/decision.json")); p = r["decision"]["signed_payload"]
r["decision"]["signed_payload"] = p.replace("allow", "deny ", 1); json.dump(r, open("record/decision.json", "w"))') || exit 2
verify "$work/changed" decision > "$work/output.txt" 2>&1; got_status=$?
if [ "$got_status" != 0 ] && [ "$(after_sentence "$work/output.txt")" = "NO SENTENCE" ] && ! grep -q -x -F "$sentence" "$work/output.txt"
then echo "ok          one word changed in the signed payload of the decision: no pass, and no sentence"
else echo "UNEXPECTED  one word changed in the signed payload of the decision -> exit $got_status"; bad=1; fi

if [ "$bad" -eq 0 ]; then echo "RESULT: PASS (every case as expected)"; else echo "RESULT: FAIL (at least one case was not as expected)"; fi
exit "$bad"
