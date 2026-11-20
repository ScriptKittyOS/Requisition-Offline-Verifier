#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
# Runs verifier/verify_offline.py with the log checkpoint flags over every case in checkpoint-vectors/manifest.json
# and compares each answer with the case's "expect": "ok" must exit 0 with the checkpoint's PASS sentence; a refusal
# code must exit 6 with "verdict: FAIL (the log checkpoint: <code>)". Offline: opens no network connection.
# Each case that names a held tree is run a second time with that tree in a held-state file (--held-state), with the
# same expected answer; a passing case that carries a proof to the key transition's tree is run a third time with an
# absent held-state file (nothing held: a pass, never a usage error).
# Then inputs of another form, made here from four passing cases: each JSON file flag given a file that holds a bare
# JSON value (false, true, null, 0, 1, "", "x", [], {}), which is a given file of the wrong form, never the flag left
# out; each member a checkpoint input may leave out (a proof's hash, its leaf_hash, the record's cosignature and the
# signature of a cosignature object) written as null, false, true, 0, "", [] and {}, which is a written member, never
# an absent one; and a co-signature beside the record (a --cosignature file, or the member beside the record in an
# answer of the evaluation environment) holding each bare value, with and without the checkpoint flags, which is a
# given co-signature of the wrong form. Each is refused by its code (a co-signature beside the record that is not one
# in the leaf: "co-signature: not a four-field envelope"), or for the held-state file is a usage
# error (exit 2, "verdict: FAIL (usage: ..."); the empty text as the cosignature member, a co-signature of no bytes,
# and a member left out, pass. The files are written in a temporary directory removed at the end.
# Usage: sh checkpoint-test.sh        Exit status 0 only if every case gets its expected answer.
set -u
cd "$(dirname "$0")" || exit 2
exec python3 -I -c '
import json, os, subprocess, sys, tempfile

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
work = tempfile.TemporaryDirectory()
runs = []
for case in manifest["cases"]:
    runs.append((case["name"], case, "flags"))
    if case["held"] is not None:
        runs.append((case["name"] + " (held-state file)", case, "state"))
        if case["expect"] == "ok" and case.get("held_to_transition_proof") is not None:
            runs.append((case["name"] + " (absent held-state)", case, "absent"))

# inputs of another form: (label, the case with one file in another form, how the held tree is given)
named = {case["name"]: case for case in manifest["cases"]}
other = []

def written(name, text):
    path = os.path.join(work.name, "other-%d-%s" % (len(other), name))
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path

BARE = ["false", "true", "null", "0", "1", "\"\"", "\"x\"", "[]", "{}"]
FLAGS = [("inclusion_proof", "included-no-held", "checkpoint_proof_malformed"),
         ("consistency_proof", "consistent-with-held", "checkpoint_proof_malformed"),
         ("key_transition", "key-transition-followed", "checkpoint_transition_unendorsed"),
         ("key_transition", "included-no-held", "checkpoint_transition_unendorsed"),
         ("held_to_transition_proof", "transition-held-older-both-proofs", "checkpoint_proof_malformed"),
         ("held_state", "consistent-with-held", "usage")]
for member, name, expect in FLAGS:
    for value in BARE:
        case = dict(named[name], expect=expect)
        flag = "--" + member.replace("_", "-")
        if member == "held_state":
            case["held_state_file"] = written("held.json", value + "\n")
            held_by = "file"
        else:
            case[member] = os.path.abspath(written(member + ".json", value + "\n"))
            held_by = "flags"
        other.append(("%s holding %s (%s)" % (flag, value, name), case, held_by))

def edited(rel, member, value):
    with open(at(rel), encoding="utf-8") as handle:
        document = json.load(handle)
    if member == "cosignature.signature":
        document["cosignature"] = {} if value is KeyError else {"signature": value}
    elif value is KeyError:
        document.pop(member, None)
    else:
        document[member] = value
    return os.path.abspath(written(os.path.basename(rel), json.dumps(document)))

VALUES = [None, False, True, 0, "", [], {}, KeyError]
MEMBERS = [("inclusion_proof", "hash", "included-no-held", "checkpoint_proof_malformed"),
           ("inclusion_proof", "leaf_hash", "included-no-held", "checkpoint_inclusion_invalid"),
           ("consistency_proof", "hash", "consistent-with-held", "checkpoint_proof_malformed"),
           ("held_to_transition_proof", "hash", "transition-held-older-both-proofs", "checkpoint_proof_malformed"),
           ("record", "cosignature", "included-no-held", "checkpoint_leaf_malformed"),
           ("record", "cosignature.signature", "included-no-held", "checkpoint_leaf_malformed")]
for file, member, name, refusal in MEMBERS:
    for value in VALUES:
        passes = (value is KeyError and member != "cosignature.signature") or (file == "record" and value == "")
        case = dict(named[name], expect="ok" if passes else refusal)
        case[file] = edited(case[file], member, value)
        shown = "left out" if value is KeyError else json.dumps(value)
        other.append(("%s of %s %s (%s)" % (member, file.replace("_", " "), shown, name), case, "flags"))

# a co-signature beside the record, given whatever it holds: a --cosignature file, and the member beside the record
# in an answer of the evaluation environment
with open(at(named["included-no-held"]["record"]), encoding="utf-8") as handle:
    envelope = handle.read()
# (under the checkpoint flags it rides in the record leaf: refused checkpoint_leaf_malformed, except the empty text, a
# co-signature of no bytes, which the post-quantum half then refuses; without the flags the post-quantum half refuses
# each: not a four-field envelope)
for value in BARE:
    for plain in (False, True):
        expect = "pq_refused" if plain or value == "\"\"" else "checkpoint_leaf_malformed"
        where = " without the checkpoint flags" if plain else ""
        case = dict(named["included-no-held"], expect=expect, plain=plain)
        case["extra"] = ["--cosignature", written("cosignature.json", value + "\n")]
        other.append(("--cosignature holding %s%s" % (value, where), case, "flags"))
        case = dict(named["included-no-held"], expect=expect, plain=plain)
        case["record"] = os.path.abspath(written("answer.json", "{\"decision\": %s, \"cosignature\": %s}\n" % (envelope, value)))
        other.append(("an answer whose cosignature is %s%s" % (value, where), case, "flags"))

runs += other
for label, case, held_by in runs:
    argv = [sys.executable, "-I", "verifier/verify_offline.py",
            "--arguments", at(manifest["arguments"]), "--act-type", manifest["act_type"],
            "--record", at(case["record"]), "--registry", at(manifest["registry"]),
            "--lab-verify", "verifier/lab-verify"]
    if case.get("plain"):
        argv += case.get("extra", [])
        run = subprocess.run(argv, capture_output=True, text=True)
        good = run.returncode not in (0, 2) and "co-signature: not a four-field envelope" in run.stdout
        print("%-11s %-38s -> %s" % ("ok" if good else "UNEXPECTED", label, "refused" if good else "exit %d" % run.returncode))
        bad = bad or not good
        continue
    argv += ["--checkpoint", at(case["checkpoint"]), "--inclusion-proof", at(case["inclusion_proof"]),
             "--witness-policy", at(case["witness_policy"])]
    if held_by == "flags" and case["held"] is not None:
        argv += ["--held-size", str(case["held"]["size"]), "--held-root", case["held"]["root"]]
    elif held_by == "state":
        with open(at(case["checkpoint"]), encoding="utf-8") as handle:
            origin = handle.readline().rstrip("\n")
        state = os.path.join(work.name, "held-%d.json" % len(argv))
        with open(state, "w", encoding="utf-8") as handle:
            json.dump({"origin": origin, "root": case["held"]["root"], "size": case["held"]["size"]}, handle)
        argv += ["--held-state", state]
    elif held_by == "absent":
        argv += ["--held-state", os.path.join(work.name, "absent.json")]
    elif held_by == "file":
        argv += ["--held-state", case["held_state_file"]]
    if case["consistency_proof"] is not None:
        argv += ["--consistency-proof", at(case["consistency_proof"])]
    if case["key_transition"] is not None:
        argv += ["--key-transition", at(case["key_transition"])]
    if case.get("held_to_transition_proof") is not None:
        argv += ["--held-to-transition-proof", at(case["held_to_transition_proof"])]
    argv += case.get("extra", [])
    run = subprocess.run(argv, capture_output=True, text=True)
    expect = case["expect"]
    if expect == "ok":
        good = run.returncode == 0 and PASS in run.stdout
        got = "PASS" if good else "exit %d" % run.returncode
    elif expect == "pq_refused":
        good = run.returncode not in (0, 2) and "co-signature: not a four-field envelope" in run.stdout
        got = "refused" if good else "exit %d" % run.returncode
    elif expect == "usage":
        good = run.returncode == 2 and "verdict: FAIL (usage: " in run.stdout
        got = "usage" if good else "exit %d" % run.returncode
    else:
        good = run.returncode == 6 and ("verdict: FAIL (the log checkpoint: %s)" % expect) in run.stdout
        got = "refused, %s" % expect if good else "exit %d" % run.returncode
    print("%-11s %-38s -> %s%s" % ("ok" if good else "UNEXPECTED", label, got,
                                  "" if good else " (expected %s)" % expect))
    bad = bad or not good

work.cleanup()
total = len(manifest["cases"])
passes = sum(1 for case in manifest["cases"] if case["expect"] == "ok")
if bad:
    print("RESULT: FAIL")
else:
    print("RESULT: PASS (%d cases: %d pass, %d refused by name, each as expected; %d runs with a held-state file; "
          "%d runs with an input of another form, each as expected)"
          % (total, passes, total - passes, len(runs) - total - len(other), len(other)))
sys.exit(1 if bad else 0)
'
