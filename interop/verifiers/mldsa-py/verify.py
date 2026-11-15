"""mldsa-py 1.0.1 (the file this repository vendors as verifier/vendor/mldsa.py) over a cases file.

usage: python3 -B -I verify.py CASES.tsv
Prints one result line. Exit 0 when no case disagrees with its expected result, 1 when any does, 2 on bad input.
"""
import hashlib
import importlib.util
import os
import sys

if len(sys.argv) != 2:
    print("usage: verify.py CASES.tsv", file=sys.stderr)
    sys.exit(2)
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "verifier", "vendor", "mldsa.py")
spec = importlib.util.spec_from_file_location("mldsa_v", path)
m = importlib.util.module_from_spec(spec)
sys.modules["mldsa_v"] = m  # dataclasses look the module up while the class is built
spec.loader.exec_module(m)


def verify(pk, sig, msg, ctx):
    try:
        m.VerificationKey(pk, parameters=m.ParameterSet.ML_DSA_87).verify(sig, msg, context=ctx)
        return True
    except (m.VerificationError, ValueError):
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
    rows = open(sys.argv[1], newline="").read().split("\n")
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
label = "mldsa-py 1.0.1 (sha256 %s, Python %s)" % (
    hashlib.sha256(open(path, "rb").read()).hexdigest()[:16], sys.version.split()[0])
print("%s: %d cases, %d disagree with the expected result %s" % (label, n, len(wrong), wrong))
sys.exit(1 if wrong else 0)
