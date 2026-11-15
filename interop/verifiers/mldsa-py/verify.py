"""mldsa-py 1.0.1 (the file this repository vendors as verifier/vendor/mldsa.py) over a cases file.

usage: python3 -B -I verify.py CASES.tsv
Prints one result line. Exit 0 when no case disagrees with its expected result, 1 when any does, 2 on bad input.
"""
import hashlib
import importlib.util
import os
import sys

if len(sys.argv) != 2:
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
label = "mldsa-py 1.0.1 (sha256 %s, Python %s)" % (
    hashlib.sha256(open(path, "rb").read()).hexdigest()[:16], sys.version.split()[0])
print("%s: %d cases, %d disagree with the expected result %s" % (label, n, len(wrong), wrong))
sys.exit(1 if wrong else 0)
