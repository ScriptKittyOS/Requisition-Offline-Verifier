#!/bin/sh
# Negative tests. Each case copies this folder, changes one thing, and expects verify.sh to FAIL.
# Offline. Leaves this folder untouched; works in a temporary directory that is removed at the end.
# Usage: sh tamper-test.sh        Exit status 0 only if the untouched copy passes and every tampered copy fails.
set -u
here=$(cd "$(dirname "$0")" && pwd) || exit 2
work=$(mktemp -d) || exit 2
trap 'rm -r "$work"' EXIT
bad=0

run_case() {  # $1 = name, $2 = expected outcome (passed|failed), $3 = python edit (may be empty)
  dir="$work/$1"
  mkdir "$dir" && cp -R "$here/record" "$here/verifier" "$here/verify.sh" "$dir/" || exit 2
  if [ -n "$3" ]; then (cd "$dir" && python3 -I -c "$3") || exit 2; fi
  if sh "$dir/verify.sh" > "$dir/output.txt" 2>&1; then got=passed; else got=failed; fi
  if [ "$got" = "$2" ]; then echo "ok          $1 -> verification ${got}, as expected"
  else echo "UNEXPECTED  $1 -> verification ${got}, expected $2"; bad=1; fi
}

edit_json='import json,base64
def load(p): return json.load(open(p))
def save(p,o): json.dump(o,open(p,"w"))
def flip(b64,i):
    raw=bytearray(base64.b64decode(b64)); raw[i]^=1; return base64.b64encode(bytes(raw)).decode()
'

run_case "untouched copy" passed ""
run_case "amount changed by one minor unit" failed "$edit_json
a=load('record/arguments.json'); a['args']['amount_minor']+=1; save('record/arguments.json',a)"
run_case "one bit flipped in the Ed25519 signature of the decision" failed "$edit_json
r=load('record/decision.json'); r['decision']['signature']=flip(r['decision']['signature'],10); save('record/decision.json',r)"
run_case "one bit flipped in the ML-DSA-87 signature of the decision" failed "$edit_json
r=load('record/decision.json'); r['cosignature']['signature']=flip(r['cosignature']['signature'],100); save('record/decision.json',r)"
run_case "one bit flipped in the Ed25519 signature of the statement" failed "$edit_json
r=load('record/statement.json'); r['statement']['signature']=flip(r['statement']['signature'],10); save('record/statement.json',r)"
run_case "one character changed in the signed payload of the decision" failed "$edit_json
r=load('record/decision.json'); p=r['decision']['signed_payload']; r['decision']['signed_payload']=p.replace('allow','deny ',1) if 'allow' in p else p[:-2]+'x'+p[-1]; save('record/decision.json',r)"
run_case "Ed25519 public key replaced by another valid key" failed "$edit_json
k=load('record/public-keys.json'); e=k['entries']; t=[x for x in e if x['signer']=='kms' and x['algorithm']=='ed25519'][0]; o=[x for x in e if x['signer']!='kms' and x['algorithm']=='ed25519'][0]
t['public_key']=o['public_key']; t['public_key_fingerprint']=o['public_key_fingerprint']; save('record/public-keys.json',k)"
run_case "Ed25519 public key replaced by the identity point, signature forged to match" failed "$edit_json
import hashlib
k=load('record/public-keys.json'); t=[x for x in k['entries'] if x['signer']=='kms' and x['algorithm']=='ed25519'][0]
ident=bytes([1])+bytes(31); t['public_key']=base64.b64encode(ident).decode(); t['public_key_fingerprint']=hashlib.sha256(ident).hexdigest(); save('record/public-keys.json',k)
B=bytes.fromhex('5866666666666666666666666666666666666666666666666666666666666666')
r=load('record/decision.json'); r['decision']['signature']=base64.b64encode(B+bytes([1])+bytes(31)).decode(); save('record/decision.json',r)"
run_case "ML-DSA-87 co-signature removed from the decision" failed "$edit_json
r=load('record/decision.json'); del r['cosignature']; save('record/decision.json',r)"

if [ "$bad" -eq 0 ]; then echo "RESULT: PASS (the untouched copy verifies; every tampered copy is refused)"; else echo "RESULT: FAIL"; fi
exit "$bad"
