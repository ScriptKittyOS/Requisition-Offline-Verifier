#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
# Runs verifier/verify_offline.py with the log checkpoint flags over every case in checkpoint-vectors/manifest.json
# and compares each answer with the case's "expect": "ok" must exit 0 with the checkpoint's PASS sentence; a refusal
# code must exit 6 with "verdict: FAIL (the log checkpoint: <code>)". Offline: opens no network connection.
# Usage: sh checkpoint-test.sh        Exit status 0 only if every case gets its expected answer.
set -u
cd "$(dirname "$0")" || exit 2
exec python3 -I -c '
import json, os, subprocess, sys

HOME = "checkpoint-vectors"
PASS = "It is included in a checkpoint of the evaluation environment"
try:
    with open(os.path.join(HOME, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
except OSError as error:
    print("cannot read %s/manifest.json: %s" % (HOME, error))
    sys.exit(2)

def at(name):
    return os.path.join(HOME, name)

bad = 0
for case in manifest["cases"]:
    argv = [sys.executable, "-I", "verifier/verify_offline.py",
            "--arguments", at(manifest["arguments"]), "--act-type", manifest["act_type"],
            "--record", at(case["record"]), "--registry", at(manifest["registry"]),
            "--lab-verify", "verifier/lab-verify",
            "--checkpoint", at(case["checkpoint"]), "--inclusion-proof", at(case["inclusion_proof"]),
            "--witness-policy", at(case["witness_policy"])]
    if case["held"] is not None:
        argv += ["--held-size", str(case["held"]["size"]), "--held-root", case["held"]["root"]]
    if case["consistency_proof"] is not None:
        argv += ["--consistency-proof", at(case["consistency_proof"])]
    if case["key_transition"] is not None:
        argv += ["--key-transition", at(case["key_transition"])]
    run = subprocess.run(argv, capture_output=True, text=True)
    expect = case["expect"]
    if expect == "ok":
        good = run.returncode == 0 and PASS in run.stdout
        got = "PASS" if good else "exit %d" % run.returncode
    else:
        good = run.returncode == 6 and ("verdict: FAIL (the log checkpoint: %s)" % expect) in run.stdout
        got = "refused, %s" % expect if good else "exit %d" % run.returncode
    print("%-11s %-38s -> %s%s" % ("ok" if good else "UNEXPECTED", case["name"], got,
                                  "" if good else " (expected %s)" % expect))
    bad = bad or not good

total = len(manifest["cases"])
passes = sum(1 for case in manifest["cases"] if case["expect"] == "ok")
if bad:
    print("RESULT: FAIL")
else:
    print("RESULT: PASS (%d cases: %d pass, %d refused by name, each as expected)" % (total, passes, total - passes))
sys.exit(1 if bad else 0)
'
