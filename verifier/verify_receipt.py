#!/usr/bin/env python3
"""verify_receipt.py — check a Trinity authority receipt's Ed25519 signature.

    python3 verify_receipt.py --receipt RECEIPT.json --registry REGISTRY.json

Python standard library only. No pip installs, no network. Tested with Python 3.11 and 3.12.

This is the SECOND, INDEPENDENT implementation. verify_receipt.exs is the reference. Two
implementations exist so an examiner who distrusts one can run the other, and so neither can drift
unnoticed — a shared corpus is run through both in CI and their verdicts must agree.

EXIT CODES AND EVERY VERDICT CASE ARE DEFINED IN ONE PLACE: VERDICTS.md, beside this file. It is
the single source, it is parsed by the cross-check test, and this header cites it rather than
restating it. Four copies of one rule is how the copies drift.

The numbers are frozen at 0, 1, 2, 5, 6 and no others may be introduced; 0, 1, 2 and 6 are this
project's proposal and are PROVISIONAL. The one distinction to
carry in your head while reading the code below: `1` accuses the receipt, `5` declines to judge it,
and collapsing them tells an examiner a receipt was forged when it was merely unverifiable.

PATTERN CREDIT — default-distrust posture, refusal with a distinct code when signer trust is not
established from bundle-local key material, flaws disclosed unprompted:

    Nathan Howard (Third Level IT / thirdlevel.ai)
    VIRP verifier, v0.1.0
    https://github.com/nhowardtli/virp/releases/tag/v0.1.0-verifier

HAND-ROLLED CRYPTO, DECLARED. The Ed25519 verification below is the RFC 8032 section 6 reference
construction, written out because Python's standard library has no Ed25519 and requiring a package
would break the no-installs property this file exists to provide. It is a NAMED EXCEPTION to the
rule against second implementations, and the exception is bounded by the cross-check corpus: this
file and verify_receipt.exs must agree on every case, including known-bad signatures, wrong keys
and truncated input. Verification only — this file never signs anything.

STRICT VERIFICATION. Before it computes the Ed25519 equation (RFC 8032 section 5.1.7) this file
refuses: a non-canonical encoding of the public key A or of R, an A or R of small order, an A of
mixed order, and an S that is not below L (see `_refusal`). Without these refusals the identity
key (01 00 .. 00) verifies R = [S]B for every message, so a signature under it proves nothing.
VERDICTS.md states the rule and its verdict. Scalar multiplication is in extended coordinates
(RFC 8032 section 5.1.4), with one inversion at the end.

THE RULE THIS FILE BOUNDS — the verifier-primitive rule (stated 2026-09-20). Nothing a
stranger is asked to check may
require a primitive this file cannot compute from the standard library: SHA-2/SHA-3/SHAKE, the
hand-written Ed25519 above, hash-based signatures. ML-DSA, BLS, pairing-based proofs, X.509 and
ECDSA are OUT — a construction that "gives the verifier X" adds a verification domain to a file
whose one stated exception is Ed25519. The import list below is the whole of what this file may
reach, and the cross-check test pins it exactly.

VERDICT CODES. Every exit-1 and exit-5 message this file writes ends with a line
`verdict_code: <code>`, the same code verify_receipt.exs and the issuing system name for that
input, written to STDERR with the message. The cross-check test compares the codes, not only the
exits, on every corpus row. Exit 0, 2 and 6 carry no code.

NO INPUT ENDS IN A STACK TRACE. A runtime that dies on an uncaught exception exits 1, which
VERDICTS.md reserves for "the receipt is bad", and writes no code line. So every named member of the
receipt and of the registry is read through `member`, which answers None for anything that is not
an object, and every input file is read through `parse_json`, which refuses (exit 2, "cannot read
input") what verify_receipt.exs refuses. A last-resort guard at the bottom of this file turns an
exception nobody foresaw into exit 2 with a one-line message, never into 0 or 1.
"""

import base64
import hashlib
import json
import re
import sys

# THE READING RULE. One rule, stated in VERDICTS.md ("how an input is read") and applied by this
# file, by verify_receipt.exs and by the issuing system: what one of them reads, all three read, to
# the same value; what one refuses, all three refuse. The three numbers below are that rule's.
#
# The largest input file that is read, in bytes. A larger file is refused (exit 2) before it is
# parsed, and no more than this many bytes plus one are ever taken into memory.
MAX_INPUT_BYTES = 1048576
# A number is read as a JSON number, which has no NaN, no Infinity and no value beyond a double. An
# integer written with more characters than this, its sign included, is not read: the issuing
# system's JSON reader refuses it, and so do both verifiers.
MAX_INTEGER_CHARACTERS = 1024
# The deepest nesting of arrays and objects that is read. Python's own recursion limit would
# otherwise decide, and decide differently from the other runtimes.
MAX_DEPTH = 64

EXIT_VERIFIED, EXIT_INVALID, EXIT_USAGE, EXIT_NO_TRUST, EXIT_COMPROMISED = 0, 1, 2, 5, 6

# --- RFC 8032 Ed25519 verification -------------------------------------------------------------
P = 2 ** 255 - 19
Q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, P - 2, P)


D = -121665 * _inv(121666) % P
I = pow(2, (P - 1) // 4, P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x


BY = 4 * _inv(5)
B = [_xrecover(BY) % P, BY % P]


def _edwards(a, b):
    x1, y1 = a
    x2, y2 = b
    k = D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + k)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - k)
    return [x3 % P, y3 % P]


def _ext_add(p, q):
    """Unified addition in extended coordinates (X, Y, Z, T), RFC 8032 section 5.1.4: no inversion."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * D * t1 * t2 % P
    dd = 2 * z1 * z2 % P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalarmult(point, e):
    """[e]point, as an affine [x, y]: double-and-add in extended coordinates, one inversion at the end."""
    result = (0, 1, 1, 0)
    addend = (point[0], point[1], 1, point[0] * point[1] % P)
    while e > 0:
        if e & 1:
            result = _ext_add(result, addend)
        addend = _ext_add(addend, addend)
        e >>= 1
    zi = _inv(result[2])
    return [result[0] * zi % P, result[1] * zi % P]


def _on_curve(point):
    x, y = point
    return (-x * x + y * y - 1 - D * x * x * y * y) % P == 0


def _decode_point(raw):
    """Decode a point as RFC 8032 section 5.1.3 requires, and no more leniently. Raises ValueError,
    beginning with the refusal's identifier, for: y >= p (`ed25519_non_canonical`), x = 0 with the
    sign bit set (`ed25519_non_canonical`), and no point on the curve for that y
    (`ed25519_not_on_curve`). The verdict is the same for all of them (see ed25519_verify)."""
    n = int.from_bytes(raw, "little")
    sign = n >> 255
    y = n & ((1 << 255) - 1)
    if y >= P:
        raise ValueError("ed25519_non_canonical: y >= p")
    x = _xrecover(y)
    point = [x, y]
    if not _on_curve(point):
        raise ValueError("ed25519_not_on_curve")
    if x == 0 and sign == 1:
        raise ValueError("ed25519_non_canonical: x = 0 with the sign bit set")
    if x & 1 != sign:
        point[0] = P - x
    return point


def _small_order(point):
    """True when [8]P is the identity: the point lies in the torsion subgroup of order 8. Decided by
    arithmetic (three doublings), never by a list of encodings."""
    for _ in range(3):
        point = _edwards(point, point)
    return point == [0, 1]


def _prime_order(point):
    """True when [L]P is the identity: P lies in the prime-order subgroup (no torsion component)."""
    return _scalarmult(point, Q) == [0, 1]


def _refusal(signature, public_key):
    """The identifier of the first reason `signature` / `public_key` is refused before the equation
    is computed, or None. A signature that is not 64 bytes or a key that is not 32 is refused as
    non-canonical, never raised. The identifiers:

      ed25519_non_canonical  A or R is not a canonical encoding (y >= p; x = 0 with the sign bit
                             set), or S >= L
      ed25519_not_on_curve   A or R is not a point
      ed25519_small_order    A or R is of small order: [8]P is the identity (decided by
                             arithmetic, never by a list of encodings)
      ed25519_mixed_order    A is not in the prime-order subgroup: [L]A is not the identity (A is
                             a multiple of B plus a point of small order). Such a key is refused
                             because implementations that reduce h modulo L and ones that do not
                             can otherwise disagree about the same signature, depending on h mod 8.
    """
    if len(signature) != 64 or len(public_key) != 32:
        return "ed25519_non_canonical"
    try:
        r = _decode_point(signature[:32])
        a = _decode_point(public_key)
    except ValueError as refusal:
        return str(refusal).split(":")[0]
    if _small_order(a) or _small_order(r):
        return "ed25519_small_order"
    if not _prime_order(a):
        return "ed25519_mixed_order"
    if int.from_bytes(signature[32:], "little") >= Q:
        return "ed25519_non_canonical"
    return None


def ed25519_verify(signature, message, public_key):
    """True when `signature` is a valid Ed25519 signature over `message` under `public_key`.

    Refuses, with False and before the equation, whatever `_refusal` names: a non-canonical
    encoding of A or R, A of small order (under the identity key every R = [S]B verifies for every
    message), R of small order, S >= L, A not in the prime-order subgroup. The verdict for all of
    them is `signature_invalid`.
    """
    if len(signature) != 64 or len(public_key) != 32:
        return False
    if _refusal(signature, public_key) is not None:
        return False
    r = _decode_point(signature[:32])
    a = _decode_point(public_key)
    s = int.from_bytes(signature[32:], "little")
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little")
    return _scalarmult(B, s) == _edwards(r, _scalarmult(a, h))


# --- verdicts ------------------------------------------------------------------------------------
# Order, and the whole of it, is VERDICTS.md's "the order the checks run in". Every trust question
# (exit 5) but the signing window precedes every accusation (exit 1), because an accusation requires
# standing. The compromised verdict (6) and the signing-window check come after the signature check,
# so only a receipt whose signature verified reaches them.
STATUSES = ("example", "active", "retired", "compromised")
ENVELOPE = ("signature", "key_id", "signed_payload", "receipt_hash")
IGNORED = ("public_key", "_note")
TS = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


def member(obj, name):
    """`obj[name]` when `obj` is a JSON object, and None for anything else (a list, a string, a
    number, null, a missing member). Every read of a named member of the receipt, the registry, a
    registry entry or the signed bytes goes through here, so a value of the wrong shape is an absent
    value and meets the same typed refusal an absent value meets. (The displayed-field check walks
    the receipt's own members, of two values already known to be objects; the note on exit 0 asks
    only whether the signed bytes, already known to be an object, carry sequence and
    previous_hash.)"""
    return obj.get(name) if isinstance(obj, dict) else None


def shown(value):
    """A value for a message: itself when it is text, otherwise a fixed phrase (never a repr of
    something the registry or the receipt chose the shape of)."""
    return value if isinstance(value, str) else "an unstated instant"


_SURROGATE = re.compile("[\ud800-\udfff]")


def _too_deep(text):
    """True when arrays and objects nest more than MAX_DEPTH deep, outside strings.

    ONE pass over the characters, with two flags: inside a string, and after a backslash inside a
    string. The time is linear in the length of the text whatever the text is; in particular a
    string that never ends is walked once, to the end of the text. A document that is not JSON may
    be counted wrongly here; it is then refused by the parser all the same."""
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "[" or char == "{":
            depth += 1
            if depth > MAX_DEPTH:
                return True
        elif char == "]" or char == "}":
            depth -= 1
    return False


def _object(pairs):
    seen = {}
    for name, value in pairs:
        if name in seen:
            raise ValueError("an object repeats the member name %r" % name)
        seen[name] = value
    return seen


def _constant(name):
    raise ValueError("%s is not a JSON number" % name)


def _integer(text):
    if len(text) > MAX_INTEGER_CHARACTERS:
        raise ValueError("an integer of more than %d characters" % MAX_INTEGER_CHARACTERS)
    return int(text)


def _float(text):
    # A negative zero written with an exponent and no fraction (`-0e5`). This reader keeps the
    # sign (-0.0); Erlang's reader, under verify_receipt.exs and the issuing system, drops it
    # (0.0). A text that two runtimes read to two values is not read. Written with a fraction
    # (`-0.0`, `-0.0e5`) every reader keeps the sign, and it is read.
    if text[:2] == "-0" and text[2:3] in ("e", "E"):
        raise ValueError("a negative zero written with an exponent and no fraction (%s)" % text)
    value = float(text)
    if value in (float("inf"), float("-inf")):
        raise ValueError("a number beyond the range of a double")
    return value


def parse_json(text):
    """The JSON value in `text`, or ValueError. Stricter than `json.loads` in exactly the ways
    verify_receipt.exs and the issuing system are: NaN, Infinity and numbers beyond a double are
    refused, and so is a negative zero written with an exponent and no fraction (`-0e5`: the two
    runtimes read it to two values); an object that repeats a member name is refused, at every
    depth, the names compared
    after their escapes are decoded (one JSON reader keeps the first occurrence and another the
    last, so a repeated name is two documents in one); an integer of more than
    MAX_INTEGER_CHARACTERS characters is refused; a string holding an unpaired surrogate is
    refused; and nesting deeper than MAX_DEPTH is refused. The input files AND the signed bytes are
    read through here: there is one rule and no exception to it."""
    if _too_deep(text):
        raise ValueError("nested more than %d levels deep" % MAX_DEPTH)
    value = json.loads(
        text,
        object_pairs_hook=_object,
        parse_constant=_constant,
        parse_int=_integer,
        parse_float=_float,
    )
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if _SURROGATE.search(item):
                raise ValueError("a string holds an unpaired surrogate")
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            for name, inner in item.items():
                if _SURROGATE.search(name):
                    raise ValueError("a member name holds an unpaired surrogate")
                stack.append(inner)
    return value


def read_json(path):
    # a bounded read: a file larger than the bound is never taken into memory whole
    with open(path, "rb") as handle:
        raw = handle.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("%s is larger than %d bytes" % (path, MAX_INPUT_BYTES))
    return parse_json(raw.decode("utf-8"))


def die(code, message, stream=sys.stderr, verdict_code=None):
    # stdout first: the public_key note is block-buffered on a pipe and would otherwise land
    # AFTER the verdict when a caller merges the streams
    sys.stdout.flush()
    if verdict_code is not None:
        message = message + "\n\nverdict_code: " + verdict_code
    print(message, file=stream)
    stream.flush()
    sys.exit(code)


# Base64 as verify_receipt.exs and the issuing system read it: groups of four characters of the
# standard alphabet, the last group padded with `=` to four, and nothing else. Python's decoder
# alone also takes a full group followed by stray `=`; the form is checked here, so that decoder
# does not decide.
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z")


def b64(value):
    if not _BASE64.match(value):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        return None


def timestamp(value):
    """The instant, as a comparable tuple, or None when the form is not the accepted one.

    Only `YYYY-MM-DDTHH:MM:SSZ` is accepted. A verifier that accepts two spellings of an instant is
    a verifier whose two implementations eventually disagree about one of them, and the disagreement
    surfaces first on a real receipt rather than in the corpus. Not coerced, not guessed: refused.

    The form alone is not enough: the text must also be a real instant of the proleptic Gregorian
    calendar. Month 01 to 12, a day that month has in that year (year 0000 is a leap year), hour 00
    to 23, minute and second 00 to 59; there is no leap second and no 24:00:00. `2026-02-30` has
    the form, and comparing it as text would place it between two real days. The arithmetic is
    written out, the same in verify_receipt.exs, so no library decides.
    """
    if not isinstance(value, str) or not TS.match(value):
        return None
    year, month, day = int(value[0:4]), int(value[5:7]), int(value[8:10])
    hour, minute, second = int(value[11:13]), int(value[14:16]), int(value[17:19])
    if month < 1 or month > 12 or hour > 23 or minute > 59 or second > 59:
        return None
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[month - 1]
    if day < 1 or day > days:
        return None
    return (value[0:4], value[5:7], value[8:10], value[11:13], value[14:16], value[17:19])


def tagged(value):
    """Type-tagged form, so equality never merges an int with a float or a bool with 1.

    VERDICTS.md's canonical encoding never merges integers and floats; Python's `==` does, and
    `True == 1` as well. Comparing untagged would make a contradiction invisible on exactly the
    values an adversary would choose. A float is compared by its exact value AND its sign, so
    `-0.0` displayed over a signed `0.0` is a contradiction (`==` calls them equal).
    """
    if value is None:
        return ("null",)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, float):
        return ("float", value.hex())
    if isinstance(value, str):
        return ("str", value)
    if isinstance(value, list):
        return ("list", [tagged(v) for v in value])
    if isinstance(value, dict):
        return ("object", sorted((k, tagged(v)) for k, v in value.items()))
    return ("other", repr(value))


def main(argv):
    # The messages carry characters outside ASCII. Under an ASCII or Latin-1 stream a strict encoder
    # would raise in the middle of a verdict, so a verified receipt could end in a stack trace; the
    # characters are written as escapes instead, and the verdict and its exit are unchanged.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")

    opts = {}
    index = 0
    while index < len(argv):
        flag = argv[index]
        if flag in ("--receipt", "--registry"):
            if index + 1 >= len(argv):
                die(EXIT_USAGE, "usage: %s requires a value" % flag)
            opts[flag[2:]] = argv[index + 1]
            index += 2
        else:
            index += 1

    if "receipt" not in opts:
        die(EXIT_USAGE, "usage: verify_receipt.py --receipt RECEIPT.json --registry REGISTRY.json")

    # DEFAULT DISTRUST. Without an independently supplied registry there is no basis to judge the
    # receipt, and taking the key from the bundle would be checking a signature against a key the
    # same party supplied. That is a refusal, not a verdict — hence 5, not 1.
    if "registry" not in opts:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — no --registry was supplied.\n\n"
            "This verifier refuses to check a signature against key material that arrived with the\n"
            "receipt. A key obtained from the same download as the evidence proves nothing:\n"
            "whoever produced the bundle chose both halves.\n\n"
            "Supply a registry you obtained INDEPENDENTLY of this receipt. It is published in\n"
            "the public repository, where every append is a dated commit you can walk and\n"
            "tampering is detectable against any older clone.\n\n"
            "A second channel — a Zenodo deposit carrying a DOI — is INTENDED and NOT YET LIVE.\n"
            "When it exists you will be able to cross-check one against the other, and\n"
            "disagreement between them will itself be an alarm. Until then there is one channel,\n"
            "and this tool says so rather than implying a check you cannot perform.",
            verdict_code="registry_not_supplied",
        )

    try:
        receipt = read_json(opts["receipt"])
        registry = read_json(opts["registry"])
    except (OSError, ValueError) as error:
        die(EXIT_USAGE, "cannot read input: %s" % error)

    if not isinstance(receipt, dict):
        die(EXIT_USAGE, "the receipt must be a JSON object")

    payload, signature, key_id = (
        member(receipt, "signed_payload"),
        member(receipt, "signature"),
        member(receipt, "key_id"),
    )
    if not all(isinstance(v, str) for v in (payload, signature, key_id)):
        die(EXIT_USAGE, "receipt must carry signed_payload, signature and key_id")

    # The receipt may carry a public_key. It is NEVER used.
    if isinstance(member(receipt, "public_key"), str):
        print("note: the receipt carries a public_key; it is ignored. Trust comes from --registry.")

    entries = member(registry, "entries")
    if not isinstance(entries, list):
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — the registry carries no entries list.",
            verdict_code="registry_missing_key",
        )

    # A key_id that is the empty text names no key, whatever the registry holds under that text.
    matches = [e for e in entries if member(e, "key_id") == key_id] if key_id != "" else []

    if not matches:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — the registry does not name key_id %r.\n\n"
            "This is not a statement that the receipt is bad. It is a statement that the registry\n"
            "you supplied gives no basis to judge it. The verifier does not fall back to any other\n"
            "key." % key_id,
            verdict_code="registry_missing_key",
        )

    # V-DUPKEY. Taking the first match would let DOCUMENT ORDER select the verdict, inside a file
    # whose governing rule is that entries are never removed or rewritten.
    if len(matches) > 1:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — the registry names key_id %r %d times.\n\n"
            "The registry is append-only: an entry is never removed and never rewritten, so one\n"
            "key_id names one key. Two entries mean the file is internally inconsistent, and\n"
            "picking either one would let the ORDER of a document decide the verdict.\n"
            "Detected on key_id only. Two entries sharing a public key under DIFFERENT key_ids is\n"
            "not this error." % (key_id, len(matches)),
            verdict_code="registry_duplicate_key",
        )

    entry = matches[0]
    status = member(entry, "status")

    # DEFAULT DENY. The registry defines exactly four statuses. Unknown standing is not good
    # standing, and a status this verifier cannot interpret is a reason to refuse, never to pass.
    if not isinstance(status, str) or status not in STATUSES:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — key_id %r carries status %r.\n\n"
            "The registry defines exactly four: example, active, retired, compromised. A status\n"
            "outside that set, or absent, is standing this verifier cannot interpret. It refuses\n"
            "rather than treating the unrecognised as the benign." % (key_id, status),
            verdict_code="key_status_not_active",
        )

    if status == "example":
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — key_id %r is an example key, not a trust root.\n\n"
            "Example entries demonstrate the registry's schema. They are generated from a published\n"
            "string, so their private half is not secret and anything they sign proves nothing."
            % key_id,
            verdict_code="key_is_example",
        )

    # The entry must hash to its own published fingerprint BEFORE its key, its window or a status of
    # active, retired or compromised is believed (an absent, undefined or example status is refused
    # first: VERDICTS.md, step 2). An entry failing its own integrity check may have been
    # substituted, and reporting a benign story read out of it would be the wrong answer.
    # an absent or non-string public_key is a fingerprint failure (the Elixir verifier's and the
    # issuing system's order; coalescing the absent key to `""` would hash to sha256(""), which
    # matches only a stated fingerprint equal to that value, and such an entry would then reach
    # the key-length check instead of failing as a fingerprint mismatch)
    published = member(entry, "public_key")
    raw_key = b64(published) if isinstance(published, str) else None
    stated = member(entry, "public_key_fingerprint")
    if raw_key is None or not isinstance(stated, str) or hashlib.sha256(raw_key).hexdigest() != stated:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — key_id %r does not hash to its own published fingerprint.\n\n"
            "public_key_fingerprint is sha256 over the RAW key bytes, lowercase hex. This entry\n"
            "fails its own integrity check, so nothing it states — its status, its window, its key —\n"
            "can be relied on." % key_id,
            verdict_code="key_fingerprint_mismatch",
        )

    # A public_key that is not 32 raw bytes is not an Ed25519 key. A defect in
    # the TRUST ROOT is a trust question, never an accusation of the receipt. The entry hashed
    # to its own fingerprint, so this is what the registry published.
    if len(raw_key) != 32:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — key_id %r publishes a public_key of %d bytes; an Ed25519\n"
            "public key is 32.\n\n"
            "The entry hashes to its own fingerprint, so this is what the registry published: not\n"
            "a key this verifier can check a signature against. Nothing the receipt says is judged."
            % (key_id, len(raw_key)),
            verdict_code="key_public_key_malformed",
        )

    valid_from, valid_to = timestamp(member(entry, "valid_from")), member(entry, "valid_to")
    if valid_from is None:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — key_id %r has no usable valid_from.\n\n"
            "Accepted form is YYYY-MM-DDTHH:MM:SSZ exactly. A window that cannot be read cannot\n"
            "place a receipt inside or outside it." % key_id,
            verdict_code="key_valid_from_unusable",
        )
    if valid_to is not None:
        valid_to = timestamp(valid_to)
        if valid_to is None:
            die(
                EXIT_NO_TRUST,
                "TRUST NOT ESTABLISHED — key_id %r has an unreadable valid_to.\n\n"
                "Accepted form is YYYY-MM-DDTHH:MM:SSZ exactly, or null for a key still signing."
                % key_id,
            verdict_code="key_valid_to_unreadable",
        )

    # The signed bytes are read by the same rule as the input files. Bytes that are not read
    # (not JSON, an object repeating a member name, too deep, a number that is not read) carry no
    # readable occurred_at: a trust question, asked before anything accuses the receipt.
    unread = ""
    try:
        signed = parse_json(payload)
        if not isinstance(signed, dict):
            signed = None
            unread = "they are not a JSON object"
    except ValueError as error:
        signed = None
        unread = "they are not JSON that every implementation reads alike (%s)" % error

    occurred = timestamp(member(signed, "occurred_at"))
    if occurred is None:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — the signed bytes carry no readable occurred_at%s.\n\n"
            "occurred_at is the only signing time a receipt carries, and it is what the key's\n"
            "signing window is checked against. Accepted form is YYYY-MM-DDTHH:MM:SSZ exactly,\n"
            "and a real calendar instant; it is refused rather than coerced, so the\n"
            "implementations cannot drift." % (": " + unread if unread else ""),
            verdict_code="signed_occurred_at_unreadable",
        )

    # --- the receipt itself. From here to the signature check everything accuses the receipt, so
    # --- it runs only once the registry has given us the standing to make an accusation. The
    # --- compromised-key and signing-window verdicts after the signature check do not accuse it.
    expected_hash = member(receipt, "receipt_hash")
    if not isinstance(expected_hash, str):
        die(
            EXIT_INVALID,
            "SIGNATURE INVALID — the receipt carries no receipt_hash.\n\n"
            "A receipt states the digest of its own signed bytes. An absent field is not a check\n"
            "to be skipped; it is a receipt that declines to be held to anything.",
            verdict_code="receipt_hash_missing",
        )
    if hashlib.sha256(payload.encode("utf-8")).hexdigest() != expected_hash:
        die(
            EXIT_INVALID,
            "SIGNATURE INVALID — the receipt's own receipt_hash does not match its signed bytes.",
            verdict_code="receipt_hash_mismatch",
        )

    for key in receipt:
        if key in ENVELOPE or key in IGNORED or key not in signed:
            continue
        if tagged(receipt[key]) != tagged(signed[key]):
            die(
                EXIT_INVALID,
                "SIGNATURE INVALID — the receipt displays %r as %r, but the SIGNED bytes say %r.\n\n"
                "A reader takes the visible field for part of the receipt. The signature covers\n"
                "only the signed bytes, so a top-level field contradicting them is a claim no\n"
                "signature stands behind." % (key, receipt[key], signed[key]),
            verdict_code="displayed_field_mismatch",
        )

    # A signature that does not decode or is not 64 raw bytes is MALFORMED --
    # the taxonomy's word, the Elixir verifier's and the issuing system's; one that decodes and
    # fails the curve check is INVALID.
    raw_signature = b64(signature)
    if raw_signature is None or len(raw_signature) != 64:
        die(
            EXIT_INVALID,
            "SIGNATURE INVALID — malformed signature or key material.",
            verdict_code="signature_malformed",
        )
    if not ed25519_verify(raw_signature, payload.encode("utf-8"), raw_key):
        die(
            EXIT_INVALID,
            "SIGNATURE INVALID — the signature does not check out against the registry's public key.",
            verdict_code="signature_invalid",
        )

    # 6 asserts the signature IS cryptographically valid, so it cannot be reached over a failed
    # verification. It sits after the checks above for that reason and not by accident.
    if status == "compromised":
        die(
            EXIT_COMPROMISED,
            "KEY COMPROMISED — the signature is cryptographically valid under key_id %r, but the\n"
            "registry marks that key compromised as of %s.\n\n"
            "WHAT THIS VERDICT CAN AND CANNOT ESTABLISH:\n\n"
            "  * The signature checks out against the published key.\n"
            "  * It does NOT establish that the issuer produced it. Anyone holding the compromised\n"
            "    private key could have.\n"
            "  * Separating a receipt signed BEFORE the compromise from one signed AFTER depends on\n"
            "    the signing time, which the receipt asserts about itself and an adversary holding\n"
            "    that key can backdate.\n\n"
            "Sound for honest history, advisory against a forger. Closing the gap requires anchoring\n"
            "signing times outside the issuing system; that is named future work.\n\n"
            "Exit code 6 is PROVISIONAL, pending reconciliation with the VIRP vocabulary."
            % (key_id, shown(member(entry, "status_changed_at"))),
            stream=sys.stdout,
        )

    # The window is half-open: valid_from <= occurred_at < valid_to. See VERDICTS.md for why the
    # published registries settle that convention rather than taste.
    if occurred < valid_from or (valid_to is not None and occurred >= valid_to):
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — the receipt says it was signed at %s, outside key_id %r's\n"
            "signing window [%s, %s).\n\n"
            "A retired key's signatures survive its retirement; a signature dated after the window\n"
            "closed was never covered by that rule. The window is half-open, so an occurred_at\n"
            "equal to valid_to is outside it.\n\n"
            "Sound for honest history, advisory against a forger: occurred_at is asserted by the\n"
            "receipt, and an adversary holding the key can backdate it."
            % (
                member(signed, "occurred_at"),
                key_id,
                member(entry, "valid_from"),
                member(entry, "valid_to"),
            ),
            verdict_code="signed_outside_key_validity",
        )

    # A signature binds the receipt's position in its chain only when the signed bytes carry both
    # members. Nothing above requires either, so the note says which is absent.
    absent = [name for name in ("sequence", "previous_hash") if name not in signed]
    if absent:
        note = (
            "Note: the signed bytes carry no %s, so this signature does not bind the receipt's "
            "position in a chain." % " and no ".join(absent)
        )
    else:
        note = (
            "Note what this attests: the signed bytes carry the receipt's sequence and previous_hash, so\n"
            "a valid signature binds the receipt's POSITION IN ITS CHAIN as well as its content."
        )
    print(
        "VERIFIED — signature is valid under key_id %r (status: %s).\n\n"
        "A retired key verifies exactly like an active one WITHIN ITS SIGNING WINDOW. Rotation does\n"
        "not invalidate receipts already issued; only new signing stops.\n\n"
        "%s" % (key_id, status, note)
    )
    sys.exit(EXIT_VERIFIED)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except SystemExit:
        raise
    except BaseException as error:
        # Last resort, for an exception no check above foresaw. Exit 2 ("nothing was measured"),
        # because neither 0 nor 1 may be said of an input this file could not evaluate, and no
        # stack trace: the type of the exception is named so the defect can be reported.
        try:
            sys.stdout.flush()
            print(
                "internal error (%s): this verifier could not evaluate the input; nothing was measured."
                % type(error).__name__,
                file=sys.stderr,
            )
        finally:
            sys.exit(EXIT_USAGE)
