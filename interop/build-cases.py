#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Derive interop/cases.tsv from this repository's record and the two test-vector files.

usage: build-cases.py [--check]
  (no argument)  write interop/cases.tsv
  --check        exit 0 if the committed interop/cases.tsv equals the derived one, 1 otherwise

Python standard library only. One case per line, six tab-separated fields:
  id  public-key  signature  message  context  expected
Fields are lower-case hex; "-" means empty; expected is 1 (must verify) or 0 (must not).

The four record cases take their bytes from the same fields verifier/verify_offline.py reads:
  signature  = base64-decoded cosignature.signature        (check_mldsa87)
  message    = UTF-8 bytes of signed_payload               (check_mldsa87)
  public key = base64-decoded public_key of the key entry named by cosignature.key_id
               (check_cosignature, check_mldsa87)
  context    = empty                                       (check_mldsa87: no context argument)
For each record there is the case as published (expected 1) and the same case with bit 0 of byte 100 of
the signature flipped (expected 0).
"""
import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(HERE, "cases.tsv")


def load(*parts):
    with open(os.path.join(ROOT, *parts), "rb") as handle:
        return json.loads(handle.read().decode("utf-8"))


def hx(data):
    return data.hex() if data else "-"


def line(case_id, pk, sig, msg, ctx, expected):
    return "\t".join([case_id, hx(pk), hx(sig), hx(msg), hx(ctx), "1" if expected else "0"]) + "\n"


def record_cases():
    keys = load("record", "public-keys.json")["entries"]
    out = []
    for name in ("statement", "decision"):
        co = load("record", name + ".json")["cosignature"]
        entry = [e for e in keys if e["key_id"] == co["key_id"]]
        if len(entry) != 1:
            raise SystemExit("no single key entry for " + co["key_id"])
        pk = base64.b64decode(entry[0]["public_key"], validate=True)
        sig = base64.b64decode(co["signature"], validate=True)
        msg = co["signed_payload"].encode("utf-8")
        flipped = bytearray(sig)
        flipped[100] ^= 0x01
        out.append(line("record-" + name, pk, sig, msg, b"", True))
        out.append(line("record-%s-flipped" % name, pk, bytes(flipped), msg, b"", False))
    # order: statement, statement-flipped, decision, decision-flipped
    return out


def acvp_cases():
    out = []
    for group in load("interop", "vectors", "acvp_sigver_mldsa87_pure_external.json")["testGroups"]:
        for t in group["tests"]:
            out.append(line("acvp-%d" % t["tcId"], bytes.fromhex(t["pk"]), bytes.fromhex(t["signature"]),
                            bytes.fromhex(t["message"]), bytes.fromhex(t["context"]), t["testPassed"]))
    return out


def wycheproof_cases():
    out = []
    for group in load("interop", "vectors", "wycheproof_mldsa_87_verify_test.json")["testGroups"]:
        pk = bytes.fromhex(group["publicKey"])
        for t in group["tests"]:
            out.append(line("wycheproof-%d" % t["tcId"], pk, bytes.fromhex(t["sig"]), bytes.fromhex(t["msg"]),
                            bytes.fromhex(t.get("ctx", "")), t["result"] == "valid"))
    return out


def derive():
    return "".join(record_cases() + acvp_cases() + wycheproof_cases()).encode("ascii")


def main(argv):
    if argv not in ([], ["--check"]):
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        return 2
    data = derive()
    if argv == ["--check"]:
        try:
            with open(OUT, "rb") as handle:
                same = handle.read() == data
        except OSError:
            same = False
        print("interop/cases.tsv %s the cases derived from record/ and interop/vectors/"
              % ("equals" if same else "DIFFERS from"))
        return 0 if same else 1
    with open(OUT, "wb") as handle:
        handle.write(data)
    print("wrote interop/cases.tsv: %d cases" % data.count(b"\n"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
