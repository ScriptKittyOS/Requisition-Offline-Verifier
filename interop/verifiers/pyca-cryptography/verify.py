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
    return b"" if s == "-" else bytes.fromhex(s)


n, wrong = 0, []
for row in open(sys.argv[1]):
    fields = row.rstrip("\n").split("\t")
    if len(fields) != 6:
        sys.exit(2)
    case_id, pk, sig, msg, ctx, expected = fields
    n += 1
    if verify(unhex(pk), unhex(sig), unhex(msg), unhex(ctx)) != (expected == "1"):
        wrong.append(case_id)
print("pyca/cryptography %s on %s: %d cases, %d disagree with the expected result %s"
      % (cryptography.__version__, backend.openssl_version_text(), n, len(wrong), wrong))
sys.exit(1 if wrong else 0)
