#!/usr/bin/env python3
"""verify_offline.py -- tie a Requisition lab record to the arguments the approvers were shown.

    python3 -I bin/verify_offline.py --arguments ARGS.json --act-type NAME --record RECORD.json \
        --lab-verify /path/to/requisition/bin/lab-verify --registry LAB-KEYS.json

ARGS.json   the arguments object exactly as shown to the approvers (for the AWS demo's argument
            rows: {"agent", "session", "tool", "args": {...}}).
NAME        the act type (e.g. payments.refund_send).
RECORD.json a lab record: the four-field envelope {signature, key_id, signed_payload, receipt_hash},
            or a /v1 answer carrying one under "statement" (GET /v1/sanction-requests/:id) or
            "decision" (POST /v1/execute).

Two independent halves, both reported:

 1. THE BINDING (this file). It recomputes act_hash = lower-case hex SHA-384 of CanonicalPayload v3
    over ARGS with "act_type" put inside (Requisition's ActHash.derive/3, act_hash.ex:36-41; label
    sha384+canonical_payload.v3) and the arguments digest = SHA-256 of CanonicalPayload v3 over ARGS
    (effector.ex:113-118), and compares them with the SIGNED metadata: act_hash, act_type,
    act_hash_alg, and display_digest (a statement) or display_projection_digest (a decision).
    bin/lab-verify alone takes --act-hash as given and never recomputes it (review-r1 §4); this is
    the half that ties the decision to these exact arguments.
 2. THE SIGNATURE: Requisition's own bin/lab-verify, unchanged, run as a stranger runs it
    (python3 -I lab-verify --receipt --registry --act-hash <the recomputed hash>). A valid lab record
    is "DEGRADED (lab)" with verdict_code lab_dev_key and exit 5: one dev key, served by the lab,
    NOT a trust root. Any other verdict is reported as it came.

    A RECORD REQUISITION'S LAB KMS SEAT SIGNED (Requisition K1; its build review 2026-11-10, item 8):
    the signed metadata says "signer": "kms" and names "kms_key_arn". bin/lab-verify then answers
    verdict_code lab_kms_key, and lab_dev_key only for a signer-dev record. Each code is accepted only
    for its own signer; a mismatch is a FAIL (exit 3). The PASS line of a signer-kms record names the
    keys the key file pins as AWS KMS keys (their ARNs) and says what offline checking cannot: that
    the private keys are held in AWS KMS is the key file's statement, not checked here.

RECORD.json may also be an ML-DSA-87 record's AgentReceipt form (lab_records.ex:86-102: the eleven
agent_receipt.v1 fields as top-level members plus "signature" and "key_id"), bare or under "receipt"
(beside "decision" in a /v1/execute answer). The signed bytes are then rebuilt by CanonicalPayload v3
over the eleven fields (agent_receipt_form_test.exs: they re-encode to the stored signed_payload);
when a "decision" envelope rides beside it, the two must name the same bytes.

 3. THE POST-QUANTUM SIGNATURE (only when the key file's entry for the record's key_id says
    "algorithm": "mldsa87"). bin/lab-verify cannot check it (Python's stdlib has no ML-DSA; it
    answers lab_signature_unchecked_mldsa87, exit 5). This file checks it with the vendored
    pure-Python verifier bin/vendor/mldsa.py (Filippo Valsorda's mldsa 1.0.1, CC0-1.0 OR 0BSD; its
    SHA-256 is pinned below and checked before it is loaded): pure ML-DSA-87 (FIPS 204), EMPTY
    context, over the UTF-8 bytes of signed_payload -- the only form the lab seat signs
    (:crypto.verify(:mldsa87, :none, ...), requisition.lab.verify_mldsa87.ex). The key entry must be
    active, its public_key base64 of 2,592 bytes hashing to its own public_key_fingerprint.

LANE 1b CO-SIGNATURES (Lane 1b PLAN.md §C.1 and its review's change 2; built from the plan's shapes,
not yet from Requisition's code). An agent-tool record keeps ONE set of signed bytes with TWO detached
signatures: the Ed25519 envelope as today, and beside it "cosignature", a four-field envelope with the
ML-DSA-87 signature over the SAME signed_payload. The signed metadata says which: "cosign":
{"algorithm": "mldsa87", "key_id": ..., "status": "signed" | "seat_absent" | "signed_bytes_over_bound"}.
When a cosignature is present (in RECORD.json beside the record, or --cosignature FILE) this file
requires: its signed_payload and receipt_hash EQUAL the record's (byte equality; nothing is
re-serialized), cosign.status "signed", its key_id equal to the signed cosign.key_id, that key's
registry entry an active mldsa87 one, and the ML-DSA-87 signature valid over those exact bytes. A
record whose signed cosign.status is "signed" with no cosignature beside it was stripped: FAIL.

--require-pq: an ML-DSA-87 signature over the record's bytes (the record's own, or a co-signature) MUST
be present and valid; a record signed "seat_absent" or "signed_bytes_over_bound", or with no cosign
member, FAILS, saying why. An outcome record (requisition.lab.outcome.v0) has no verdict: it is printed
as "outcome reported by the caller (not proof the effect happened)".

POLICY (W1-1, W1-4, W1-5 of the 2026-11-11 crypto review). THE KEY RULE (requisition's lab_key_rule.ex is its text;
the same one function is in requisition_aws/keys.py and bin/verify_chain.py; tests/vectors/key_rule_vectors.v1.json
its shared vectors): a signature verifies under a key only if the key is not compromised/revoked, is active or retired,
and the record's signed occurred_at lies in [valid_from, valid_to) -- so a retired key verifies its own window and
nothing after it (key_not_valid_at_signing). Here it governs the ML-DSA-87 half; bin/lab-verify's reference verifier
governs the Ed25519 half.
--accept-signer LABEL (repeatable): refuse (signer_not_accepted) any record whose key entry's signer is not one of
  the labels, in both halves (forwarded to bin/lab-verify). Without it any signer verifies (a dev key's PASS line
  says DEGRADED (lab) and names the dev keys). --accept-signer kms makes KMS custody bound what verifies.
POST-QUANTUM BY POLICY: when the key file holds an ML-DSA-87 key of the record's signer that was usable at the record's
signed instant, an ML-DSA-87 signature (the record's own, or a co-signature) is REQUIRED without --require-pq: the
record's own ``cosign`` claim does not decide it. --allow-classical-only lifts that (explicit); --require-pq still
requires it of every record. A flag may only tighten, except --allow-classical-only, which exists to be seen.

EXIT: 0 every half passes (binding equal; lab-verify lab_dev_key for a signer-dev record and lab_kms_key
for a signer-kms one, or for an ML-DSA-87 record
lab_signature_unchecked_mldsa87 AND the ML-DSA-87 signature valid here); 1 a binding mismatch or an
unreadable record; 3 lab-verify did not answer as above; 4 the ML-DSA-87 signature, the co-signature or its key
entry fails, or --require-pq is not met; 2 usage. Standard library and the one vendored file only.

The encoder below is a second copy of requisition_aws/canonical.py's (this file must run under -I,
which cannot import the package); tests/test_verify_offline.py pins the two equal.
"""

import base64
import binascii
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import types

LABEL = "sha384+canonical_payload.v3"
ENVELOPE = ("signature", "key_id", "signed_payload", "receipt_hash")
EXIT_OK, EXIT_MISMATCH, EXIT_USAGE, EXIT_LAB_VERIFY, EXIT_SIGNATURE = 0, 1, 2, 3, 4
# the eleven agent_receipt.v1 fields (authority_receipts.ex @hashed_fields; agent_receipt_form_test.exs)
ELEVEN = ("chain_scope", "sequence", "receipt_type", "subject_type", "subject_id", "status",
          "payload_hash", "previous_hash", "occurred_at", "metadata", "schema_version")
# the vendored verifier: bin/vendor/mldsa.py, PyPI mldsa 1.0.1 (bin/vendor/VENDORED.md)
MLDSA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor", "mldsa.py")
MLDSA_SHA256 = "0e8885d01ed76919f3152caa160f90949c03efc6a3748865aaf4beb2737c7a4a"
MLDSA87_PUBLIC_BYTES, MLDSA87_SIGNATURE_BYTES = 2592, 4627  # FIPS 204 Table 2; bin/lab-verify:112-113
# this file checks every co-signature itself (check_cosignature), so bin/lab-verify is told not to say it did not
CALLER_CHECKS_COSIGNATURE = "--cosignature-checked-by-caller"
OUTCOME_KIND = "requisition.lab.outcome.v0"  # Lane 1b PLAN.md §B.1 item 4
PQ_ABSENT_WHY = {
    "seat_absent": "the record's signed cosign.status is seat_absent: Requisition's ML-DSA-87 seat was not "
                   "running when it was signed, so it carries an Ed25519 signature only",
    "signed_bytes_over_bound": "the record's signed cosign.status is signed_bytes_over_bound: its signed bytes "
                               "exceed ML-DSA-87's 4,096-byte bound in the lab, so it was issued Ed25519 only",
    None: "the record carries no cosign member and no ML-DSA-87 signature: it makes no post-quantum claim "
          "(a record from before Lane 1b, or not an agent-tool row)",
}

_SHORT = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r", 0x22: '\\"', 0x5C: "\\\\"}


class Refused(ValueError):
    pass


def _string(value):
    value.encode("utf-8")  # a lone surrogate raises
    out = []
    for ch in value:
        cp = ord(ch)
        if cp in _SHORT:
            out.append(_SHORT[cp])
        elif cp < 0x20:
            out.append("\\u%04X" % cp)
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _encode(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise Refused("a float is outside the act-hash domain")
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise Refused("a non-string key")
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_string(k) + ":" + _encode(v) for k, v in items) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_encode(v) for v in value) + "]"
    raise Refused("an unencodable value")


def encode(value):
    return _encode(value).encode("utf-8")


def act_hash(act_type, args):
    if not isinstance(args, dict) or "act_type" in args:
        raise Refused("the arguments must be an object without an act_type member")
    return hashlib.sha384(encode(dict(args, act_type=act_type))).hexdigest()


def display_digest(args):
    return hashlib.sha256(encode(args)).hexdigest()


# --- THE KEY RULE: a byte copy of requisition_aws/keys.py's (this file runs under -I and cannot import the
# package; tests/test_key_rule.py pins the sources equal and runs the shared vectors against both) ---------------

_INSTANT_SHAPE = "dddd-dd-ddTdd:dd:ddZ"


def _is_instant(value):
    """Exactly ``YYYY-MM-DDTHH:MM:SSZ`` (ASCII digits only), the one spelling every verifier accepts."""
    return (isinstance(value, str) and len(value) == 20
            and all((c in "0123456789") if m == "d" else c == m for c, m in zip(value, _INSTANT_SHAPE)))


def key_standing(entry, occurred_at, accept_signers=None):
    """None when ``entry`` may be used for a record signed at ``occurred_at``, else the reason. See the module doc."""
    if accept_signers is not None and not accept_signers:
        raise ValueError("an empty accepted-signers set is a configuration error, never 'any'")
    status = entry.get("status")
    if status in ("compromised", "revoked"):
        return "key_revoked"
    if status not in ("active", "retired"):
        return "key_status_unusable"
    valid_from, valid_to = entry.get("valid_from"), entry.get("valid_to")
    if status == "retired" and valid_to is None:
        return "key_status_unusable"  # retired with no end is no standing at all
    if not _is_instant(valid_from) or (valid_to is not None and not _is_instant(valid_to)):
        return "key_window_unreadable"
    if not _is_instant(occurred_at):
        return "signed_instant_unreadable"
    if occurred_at < valid_from or (valid_to is not None and occurred_at >= valid_to):
        return "key_not_valid_at_signing"
    if accept_signers is not None and entry.get("signer") not in accept_signers:
        return "signer_not_accepted"
    return None


def _no_dupes(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate member")
    return dict(pairs)


def _no_constant(name):
    raise ValueError("%s is not JSON (RFC 8259 section 6)" % name)


def _finite_float(lexeme):
    value = float(lexeme)
    if value in (float("inf"), float("-inf")):  # 1e400: a valid lexeme, never an infinite float here
        raise ValueError("a number outside the double range (RFC 8259 section 9 limit)")
    return value


MAX_DEPTH = 64  # containers; the 65th is refused (requisition-ts src/json.ts MAX_DEPTH; lab_key_rule.ex decode_bounded/1)
MAX_INTEGER = 9_007_199_254_740_991  # CanonicalPayload v3's integer range (canonical.MAX_INTEGER)


def _check_depth(text):
    depth, in_string, escaped = 0, False, False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("nesting deeper than %d" % MAX_DEPTH)
        elif ch in "]}":
            depth -= 1


def _bounded_int(lexeme):
    value = int(lexeme)
    if not -MAX_INTEGER <= value <= MAX_INTEGER:
        raise ValueError("an integer outside +-(2^53-1), the canonical form's range")
    return value


def loads_strict(data):
    """requisition_aws.client.loads_strict's rule, copied (this file runs under -I and cannot import the
    package; tests/test_cli_strict_json.py pins the two equal): duplicate members, NaN/Infinity/-Infinity
    and numbers that are not finite doubles refused; bytes decoded as strict UTF-8 (no UTF-16/32 detection,
    no surrogatepass); a BOM refused; nesting deeper than MAX_DEPTH (64) containers and an integer outside
    +-(2^53-1) refused (F-5). Every refusal is a ValueError."""
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode("utf-8")
    _check_depth(data)
    return json.loads(data, object_pairs_hook=_no_dupes, parse_constant=_no_constant, parse_float=_finite_float, parse_int=_bounded_int)


def load(path):
    with open(path, "rb") as handle:
        return loads_strict(handle.read())


def _is_envelope(obj):
    return isinstance(obj, dict) and all(isinstance(obj.get(k), str) for k in ENVELOPE)


def _is_form(obj):
    return (isinstance(obj, dict) and all(k in obj for k in ELEVEN)
            and isinstance(obj.get("signature"), str) and isinstance(obj.get("key_id"), str))


def envelope_from_form(form):
    """An AgentReceipt form -> the four-field envelope: the signed bytes are CanonicalPayload v3 over
    the eleven fields exactly as received (never re-derived from anything else)."""
    extra = set(form) - set(ELEVEN) - {"signature", "key_id"}
    if extra:
        raise Refused("the AgentReceipt form carries members outside the eleven fields: %s" % sorted(extra))
    payload = encode({k: form[k] for k in ELEVEN}).decode("utf-8")
    return {"signature": form["signature"], "key_id": form["key_id"], "signed_payload": payload,
            "receipt_hash": hashlib.sha256(payload.encode("utf-8")).hexdigest()}


def envelope_of(record):
    if _is_envelope(record):
        return record
    if _is_form(record):
        return envelope_from_form(record)
    if not isinstance(record, dict):
        raise Refused("no lab record found")
    form = record.get("receipt")
    if _is_form(form):
        built = envelope_from_form(form)
        beside = record.get("decision")
        if beside is not None:
            if not _is_envelope(beside):
                raise Refused("the decision beside the receipt is not a four-field envelope")
            if (beside["signed_payload"], beside["signature"], beside["key_id"]) != (
                    built["signed_payload"], built["signature"], built["key_id"]):
                raise Refused("the receipt form and the decision envelope beside it name different bytes")
        return built
    for key in ("decision", "statement", "record"):
        if _is_envelope(record.get(key)):
            return record[key]
    raise Refused("no four-field lab record or AgentReceipt form found")


def cosignature_of(record):
    """The Lane 1b co-signature beside the record in a /v1 answer, or None."""
    if not isinstance(record, dict) or _is_envelope(record) or _is_form(record):
        return None
    return record.get("cosignature")


# --- the post-quantum half ---------------------------------------------------------------------


def load_mldsa(path=MLDSA_PATH, pinned=MLDSA_SHA256):
    """Load the vendored verifier by path (python -I does not put this directory on sys.path),
    refusing it unless its bytes hash to the pinned SHA-256."""
    with open(path, "rb") as handle:
        source = handle.read()
    if hashlib.sha256(source).hexdigest() != pinned:
        raise Refused("bin/vendor/mldsa.py is not the pinned file (sha256 %s)" % pinned)
    name = "requisition_vendored_mldsa"
    module = types.ModuleType(name)
    module.__file__ = path
    sys.modules[name] = module  # dataclasses look the module up while the class is built
    exec(compile(source, path, "exec"), module.__dict__)
    return module


def _b64(text):
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, TypeError, ValueError):
        return None


def key_entry(registry, key_id):
    entries = registry.get("entries") if isinstance(registry, dict) else None
    matches = [e for e in entries if isinstance(e, dict) and e.get("key_id") == key_id] if isinstance(entries, list) else []
    return matches[0] if len(matches) == 1 else None


def check_mldsa87(envelope, entry, mldsa=None, accept_signers=None):
    """Return (lines, ok). Pure ML-DSA-87, empty context, over signed_payload's UTF-8 bytes, under THE KEY RULE."""
    key_id = envelope["key_id"]
    reason = key_standing(entry, _occurred_at(envelope), accept_signers)
    if reason is not None:
        return ["key entry %s: refused by the key rule: %s (status %r, signer %r)"
                % (key_id, reason, entry.get("status"), entry.get("signer"))], False
    raw = _b64(entry.get("public_key")) if isinstance(entry.get("public_key"), str) else None
    if raw is None or hashlib.sha256(raw).hexdigest() != entry.get("public_key_fingerprint"):
        return ["key entry %s: public_key does not hash to its public_key_fingerprint" % key_id], False
    if len(raw) != MLDSA87_PUBLIC_BYTES:
        return ["key entry %s: a %d-byte key, not ML-DSA-87's %d" % (key_id, len(raw), MLDSA87_PUBLIC_BYTES)], False
    signature = _b64(envelope["signature"])
    if signature is None or len(signature) != MLDSA87_SIGNATURE_BYTES:
        return ["signature: not base64 of %d bytes (ML-DSA-87's size)" % MLDSA87_SIGNATURE_BYTES], False
    mldsa = mldsa or load_mldsa()
    try:
        key = mldsa.VerificationKey(raw, parameters=mldsa.ParameterSet.ML_DSA_87)
        key.verify(signature, envelope["signed_payload"].encode("utf-8"))
    except (mldsa.VerificationError, ValueError) as error:
        return ["ML-DSA-87 signature: INVALID under %s (%s)" % (key_id, error)], False
    return ["ML-DSA-87 signature: valid under %s (key fingerprint %s), pure, empty context, checked by "
            "the vendored mldsa 1.0.1 (sha256 %s...)" % (key_id, entry["public_key_fingerprint"], MLDSA_SHA256[:16])], True


def _occurred_at(envelope):
    try:
        signed = loads_strict(envelope["signed_payload"])
    except (ValueError, KeyError, TypeError):
        return None
    return signed.get("occurred_at") if isinstance(signed, dict) else None


def pq_expected(registry, envelope):
    """W1-5: True when the pinned key file holds an ML-DSA-87 key of the SAME signer as the record's key that was
    usable at the record's signed instant -- the file says this signer signs post-quantum, whatever the record's own
    ``cosign`` member claims."""
    entries = registry.get("entries") if isinstance(registry, dict) else None
    mine = key_entry(registry, envelope["key_id"])
    at = _occurred_at(envelope)
    if mine is None or at is None or not isinstance(entries, list):
        return False
    return any(isinstance(e, dict) and e.get("algorithm") == "mldsa87" and e.get("signer") == mine.get("signer")
               and key_standing(e, at) is None for e in entries)


def check_binding(args, act_type, envelope):
    """Return (lines, ok, recomputed_act_hash)."""
    lines, ok = [], True
    recomputed = act_hash(act_type, args)
    digest = display_digest(args)
    if hashlib.sha256(envelope["signed_payload"].encode("utf-8")).hexdigest() != envelope["receipt_hash"]:
        return ["receipt_hash: MISMATCH (not the SHA-256 of signed_payload)"], False, recomputed
    signed = loads_strict(envelope["signed_payload"])
    md = signed.get("metadata") if isinstance(signed, dict) else None
    if not isinstance(md, dict):
        return ["signed_payload: no metadata"], False, recomputed
    kind = signed.get("receipt_type")
    lines.append("record: %s (receipt_hash %s)" % (kind, envelope["receipt_hash"]))
    if kind == OUTCOME_KIND:
        lines.append("outcome reported by the caller (not proof the effect happened): %s, result_digest %s, "
                     "evidence %s, reported_at %s" % (md.get("outcome"), md.get("result_digest"),
                                                     md.get("evidence"), md.get("reported_at")))
        if "verdict" in md:
            lines.append("verdict: PRESENT on an outcome record, which must carry none")
            ok = False
    elif "verdict" in md:
        lines.append("signed verdict: %s%s" % (md["verdict"], (" " + md["code"]) if md.get("code") else ""))
    digest_member = "display_projection_digest" if kind == "requisition.lab.decision.v0" else "display_digest"
    signed_hash = md.get("act_hash")
    if not isinstance(signed_hash, str) and isinstance(signed.get("payload_hash"), str):
        # an agent_receipt.v1 record that binds its act in payload_hash (bin/lab-verify's rule)
        signed_hash = signed["payload_hash"]
    checks = [
        ("act_hash", recomputed, signed_hash),
        ("act_type", act_type, md.get("act_type")),
        ("act_hash_alg", LABEL, md.get("act_hash_alg")),
    ]
    if digest_member in md:
        checks.append((digest_member, digest, md.get(digest_member)))
    else:
        lines.append("%s: not signed in this record (the act_hash above binds every argument)" % digest_member)
    for name, mine, theirs in checks:
        same = mine == theirs
        ok = ok and same
        lines.append("%s: %s (recomputed %s, signed %s)" % (name, "equal" if same else "MISMATCH", mine, theirs))
    return lines, ok, recomputed


def run_lab_verify(lab_verify, envelope, registry, expected_hash, python, accept_signers=()):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "record.json")
        with open(path, "w") as handle:
            json.dump(envelope, handle)
        proc = subprocess.run(
            [python, "-I", lab_verify, "--receipt", path, "--registry", registry, "--act-hash", expected_hash,
             CALLER_CHECKS_COSIGNATURE] + [a for label in accept_signers for a in ("--accept-signer", label)],
            capture_output=True,
            text=True,
            timeout=60,
        )
    output = (proc.stdout + proc.stderr).strip()
    code = None
    for line in output.splitlines():
        if line.startswith("verdict_code:"):
            code = line.split(":", 1)[1].strip()
    return proc.returncode, code, output


def check_cosignature(envelope, cosignature, registry, mldsa=None, accept_signers=None):
    """Return (lines, ok, present). Lane 1b's co-signature over the SAME bytes (byte equality)."""
    signed = loads_strict(envelope["signed_payload"])
    md = signed.get("metadata") if isinstance(signed, dict) else {}
    cosign = md.get("cosign") if isinstance(md, dict) else None
    status = cosign.get("status") if isinstance(cosign, dict) else None
    lines = ["signed cosign: %s" % (json.dumps(cosign, sort_keys=True) if cosign is not None else "absent")]
    if cosignature is None:
        if status == "signed":
            return lines + ["co-signature: MISSING, yet the signed bytes say it exists: stripped"], False, False
        return lines + ["co-signature: none"], True, False
    if not _is_envelope(cosignature):
        return lines + ["co-signature: not a four-field envelope"], False, True
    if cosignature["signed_payload"] != envelope["signed_payload"] or cosignature["receipt_hash"] != envelope["receipt_hash"]:
        return lines + ["co-signature: does NOT cover the record's own bytes (signed_payload or receipt_hash differ)"], False, True
    lines.append("co-signature covers the same bytes: signed_payload and receipt_hash byte-equal")
    if status != "signed":
        return lines + ["co-signature present but the signed cosign.status is %r, not signed" % status], False, True
    if cosignature["key_id"] != cosign.get("key_id"):
        return lines + ["co-signature key_id %r is not the signed cosign.key_id %r" % (cosignature["key_id"], cosign.get("key_id"))], False, True
    entry = key_entry(registry, cosignature["key_id"])
    if entry is None or entry.get("algorithm") != "mldsa87":
        return lines + ["co-signature key %r: no single mldsa87 entry in the key file" % cosignature["key_id"]], False, True
    pq_lines, pq_ok = check_mldsa87({"signature": cosignature["signature"], "key_id": cosignature["key_id"],
                                     "signed_payload": envelope["signed_payload"]}, entry, mldsa, accept_signers)
    return lines + pq_lines, pq_ok, True


def main(argv):
    opts, i = {}, 0
    flags = ("--arguments", "--act-type", "--record", "--lab-verify", "--registry", "--python", "--cosignature")
    while i < len(argv):
        if argv[i] == "--require-pq":
            opts["require-pq"] = True
            i += 1
        elif argv[i] == "--allow-classical-only":
            opts["allow-classical-only"] = True
            i += 1
        elif argv[i] == "--accept-signer" and i + 1 < len(argv) and argv[i + 1]:
            opts.setdefault("accept-signer", []).append(argv[i + 1])
            i += 2
        elif argv[i] in flags and i + 1 < len(argv):
            opts[argv[i][2:]] = argv[i + 1]
            i += 2
        else:
            print("usage: verify_offline.py --arguments ARGS.json --act-type NAME --record RECORD.json "
                  "--lab-verify PATH --registry KEYS.json [--cosignature COSIG.json] [--require-pq] [--allow-classical-only] "
                  "[--accept-signer LABEL]... [--python python3]",
                  file=sys.stderr)
            return EXIT_USAGE
    missing = [f for f in ("arguments", "act-type", "record", "lab-verify", "registry") if f not in opts]
    if missing:
        print("usage: missing --" + ", --".join(missing), file=sys.stderr)
        return EXIT_USAGE
    try:
        args = load(opts["arguments"])
        record = load(opts["record"])
        envelope = envelope_of(record)
        cosignature = load(opts["cosignature"]) if "cosignature" in opts else cosignature_of(record)
        registry = load(opts["registry"])
        lines, ok, recomputed = check_binding(args, opts["act-type"], envelope)
    except (OSError, ValueError) as error:
        print("binding: UNREADABLE (%s)" % error)
        print("verdict: FAIL")
        return EXIT_MISMATCH
    entry = key_entry(registry, envelope["key_id"])
    pq = entry is not None and entry.get("algorithm") == "mldsa87"
    print("== 1. the binding: these arguments, this act type, this signed record")
    for line in lines:
        print("  " + line)
    print("== 2. the record: bin/lab-verify, unchanged")
    accept = opts.get("accept-signer")
    exit_code, verdict_code, output = run_lab_verify(
        opts["lab-verify"], envelope, opts["registry"], recomputed, opts.get("python", sys.executable or "python3"),
        accept or ()
    )
    for line in output.splitlines():
        print("  | " + line)
    print("  lab-verify exit %d, verdict_code %s" % (exit_code, verdict_code))
    pq_ok, pq_present = True, False
    # The signed metadata, read ONLY from a record the binding accepted: check_binding parsed these exact
    # bytes with loads_strict inside the try above and returned ok only with a metadata object. A record
    # it refused (duplicate member, an array, a hash mismatch) gets {} and reaches the clean FAIL below,
    # never a traceback (Requisition K1, delta review of k1-verify-r2, item 1).
    signed_md = loads_strict(envelope["signed_payload"])["metadata"] if ok else {}
    kms = signed_md.get("signer") == "kms"
    expected_code = "lab_kms_key" if kms else "lab_dev_key"
    if pq:
        print("== 3. the post-quantum signature: ML-DSA-87 (FIPS 204), the record's own, checked here")
        try:
            pq_lines, pq_ok = check_mldsa87(envelope, entry, accept_signers=frozenset(accept) if accept else None)
        except (OSError, ValueError) as error:
            pq_lines, pq_ok = ["the vendored verifier could not be loaded (%s)" % error], False
        pq_present = pq_ok
        lab_ok = exit_code == 5 and verdict_code == "lab_signature_unchecked_mldsa87"
    else:
        print("== 3. the post-quantum co-signature: ML-DSA-87 (FIPS 204) over the same bytes, checked here")
        try:
            pq_lines, pq_ok, pq_present = check_cosignature(envelope, cosignature, registry,
                                                            accept_signers=frozenset(accept) if accept else None)
        except (OSError, ValueError) as error:
            pq_lines, pq_ok, pq_present = ["the co-signature could not be checked (%s)" % error], False, True
        lab_ok = exit_code == 5 and verdict_code == expected_code
    for line in pq_lines:
        print("  " + line)
    if not pq and pq_present and pq_ok and lab_ok:
        print("  both signatures verified: the Ed25519 signature (by bin/lab-verify) and the ML-DSA-87 co-signature (by this tool)")
    pq_required_unmet = None
    # W1-5: post-quantum is required by --require-pq, AND by the pinned key file itself when it holds an ML-DSA-87 key
    # of the record's signer (the record's own cosign claim decides nothing); only --allow-classical-only lifts the
    # second, explicitly. A flag may only tighten.
    by_policy = (not opts.get("require-pq") and not opts.get("allow-classical-only") and not pq
                 and ok and pq_expected(registry, envelope))
    if by_policy:
        print("  post-quantum REQUIRED by the key file: it holds an ML-DSA-87 key of this signer (lift with --allow-classical-only)")
    if (opts.get("require-pq") or by_policy) and not (pq_present and pq_ok):
        cosign = signed_md.get("cosign")
        status = cosign.get("status") if isinstance(cosign, dict) else None
        pq_required_unmet = PQ_ABSENT_WHY.get(status, "the record's signed cosign.status is %r" % status) \
            if not pq_present else "the ML-DSA-87 signature does not check out (above)"
        print("  post-quantum REQUIRED (%s): NOT MET -- %s"
              % ("--require-pq" if opts.get("require-pq") else "key file policy", pq_required_unmet))
    elif opts.get("require-pq") or by_policy:
        print("  post-quantum REQUIRED (--require-pq): met")
    if not ok:
        print("verdict: FAIL (the signed record does not bind these arguments)")
        return EXIT_MISMATCH
    if not lab_ok:
        print("verdict: FAIL (lab-verify did not answer %s for this record's signed signer %r)"
              % ("lab_signature_unchecked_mldsa87" if pq else expected_code, signed_md.get("signer")))
        return EXIT_LAB_VERIFY
    if not pq_ok:
        print("verdict: FAIL (the ML-DSA-87 signature, the co-signature or its key entry does not check out)")
        return EXIT_SIGNATURE
    if pq_required_unmet:
        print("verdict: FAIL (post-quantum required: %s)" % pq_required_unmet)
        return EXIT_SIGNATURE
    if pq:
        signatures = "its ML-DSA-87 (post-quantum) signature is valid"
    elif pq_present:
        signatures = ("its Ed25519 signature AND its ML-DSA-87 (post-quantum) co-signature over the same bytes "
                      "are valid")
    else:
        signatures = "its Ed25519 signature is valid"
    kind = loads_strict(envelope["signed_payload"]).get("receipt_type")
    said = ("What it records is the caller's report, above, not proof the effect happened." if kind == OUTCOME_KIND
            else "What it decided is its signed verdict, above.")
    if kms:
        cosign = signed_md.get("cosign") if isinstance(signed_md.get("cosign"), dict) else {}
        arns = [a for a in (signed_md.get("kms_key_arn"), cosign.get("kms_key_arn")) if isinstance(a, str)]
        keys = ("the key file pins as AWS KMS keys %s (lab profile, lab keys, not a trust root; KMS custody "
                "is the key file's statement, not checked offline)" % ", ".join(arns))
    else:
        keys = "(DEGRADED (lab): dev keys served by the lab, not a trust root)"
    print("verdict: PASS -- the record is bound to these arguments and %s under the LAB key(s) %s. %s"
          % (signatures, keys, said))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
