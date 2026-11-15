"""pyca/cryptography (ML-DSA-87 through its OpenSSL backend) over a cases file.

usage: python3 -B -I verify.py CASES.tsv
Prints one result line. Exit 0 when no case disagrees with its expected result, 1 when any does, 2 on bad input.
"""
import sys

import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.asymmetric import mldsa

if len(sys.argv) != 2:
    sys.exit(2)


def verify(pk, sig, msg, ctx):
    try:
        mldsa.MLDSA87PublicKey.from_public_bytes(pk).verify(sig, msg, ctx or None)
        return True
    except (InvalidSignature, ValueError):
        return False


def unhex(s):
    if s == "-":
        return b""
    if not s or len(s) % 2 or any(c not in "0123456789abcdefABCDEF" for c in s):
        print("bad hex", file=sys.stderr)
        sys.exit(2)
    return bytes.fromhex(s)


n, wrong = 0, []
try:
    rows = open(sys.argv[1]).read().split("\n")
except (OSError, UnicodeDecodeError) as e:
    print("cannot read %s" % sys.argv[1], file=sys.stderr)
    sys.exit(2)
for row in rows:
    if not row:
        continue
    fields = row.rstrip("\r").split("\t")
    if len(fields) != 6:
        print("bad line", file=sys.stderr)
        sys.exit(2)
    case_id, pk, sig, msg, ctx, expected = fields
    if expected not in ("0", "1"):
        print("bad expected result in case %s" % case_id, file=sys.stderr)
        sys.exit(2)
    args = (unhex(pk), unhex(sig), unhex(msg), unhex(ctx))
    n += 1
    if verify(*args) != (expected == "1"):
        wrong.append(case_id)
if n == 0:
    print("no cases", file=sys.stderr)
    sys.exit(2)
print("pyca/cryptography %s on %s: %d cases, %d disagree with the expected result %s"
      % (cryptography.__version__, backend.openssl_version_text(), n, len(wrong), wrong))
sys.exit(1 if wrong else 0)
