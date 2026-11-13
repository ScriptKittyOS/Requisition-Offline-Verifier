# Provenance

Where every file in this repository came from. Digests are SHA-256. `SHA256SUMS` lists every file.

## The records

Produced on 2026-11-13 by one run of the Requisition evaluation environment, signed by two keys in AWS KMS
(`us-east-2`). The files are byte-for-byte the files that run wrote; only their names were changed.

| File | Name in the run | SHA-256 |
|---|---|---|
| `record/statement.json` | `statement.json` | `f169706fe73dc2f9ba39d3086d99ea42f93ef634e11f0ec2be4ec57122366612` |
| `record/decision.json` | `v0-16.json` | `8da809260a7a5f292407532315d78d7750ef024e780ea8b6e565decc6409fe5f` |
| `record/arguments.json` | `arguments.json` | `2381724c2474fe72b6d184f6b1a40adda4ed952e1b55a1d801abc526aeee8333` |
| `record/public-keys.json` | `lab-keys-kms.json` | `16fe8eda6223197a5681752f32c723ea12d3e6087e465f4445b920e6de8ce3a3` |

The public key file was written on the signing host from the answers of AWS KMS `GetPublicKey` for the two
keys. Before publication the two public keys in it were compared with `GetPublicKey` answers fetched
separately, as the account that owns the keys.

## The verifier

Copied from two private source repositories at the commits below.

| File | Source path | Source commit | SHA-256 | Changes |
|---|---|---|---|---|
| `verifier/verify_offline.py` | `bin/verify_offline.py` (requisition-aws) | `97a2fceeafc3` | `e4a525c6f10a53e438e0a27b83820f545029d821dab3ca537921e7a21243d82f` | none |
| `verifier/lab-verify` | `bin/lab-verify` (requisition) | `22c75da4729a` | `5a41bf7352dac4363777da4f0fe662e174c43d1e5db5856b12d5b28c4f8e07cd` | one: see below |
| `verifier/verify_receipt.py` | `bench/holytrinity-v2/verifier/verify_receipt.py` (requisition) | `22c75da4729a` | `0f5f3a884f781a14a621946c1464fb96d561935494bbe0302bbef7f6f4b18dc7` | none |
| `verifier/vendor/mldsa.py` | mldsa-py 1.0.1, `src/mldsa/mldsa.py` | upstream release | `0e8885d01ed76919f3152caa160f90949c03efc6a3748865aaf4beb2737c7a4a` | none |
| `verifier/vendor/LICENSE.mldsa` | mldsa-py 1.0.1, `LICENSE` | upstream release | `74b344a43288283ca7896b38d859bd6b91035110bb9c69856afbc60a01ff65e4` | none |

**The one change.** In its source tree `lab-verify` finds `verify_receipt.py` at
`../bench/holytrinity-v2/verifier/`. Here the two files sit in one directory, so the constant that holds
that path was changed. Nothing else differs. The complete difference from the source file:

```diff
122,128c122
< VERIFIER = os.path.join(
<     os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
<     "bench",
<     "holytrinity-v2",
<     "verifier",
<     "verify_receipt.py",
< )
---
> VERIFIER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "verify_receipt.py")
```

Because the source files are unchanged, their comments and some output lines use the source trees' paths
(`bin/lab-verify`, `bin/vendor/mldsa.py`) and the project's internal reference numbers (`G-…`, `REQ-…`).

## How this copy was checked before publication

- `sh verify.sh` passes on Python 3.11.15 and 3.12.3, in an empty environment (`env -i`), with identical output.
- A system-call trace (`strace -f -e trace=network`) of `sh verify.sh` shows no network system calls.
- `sh tamper-test.sh` passes: the untouched copy verifies and each of the eight tampered copies is refused.
- The strict Ed25519 rules in `verify_receipt.py` and `lab-verify` were reviewed independently against 102
  adversarial inputs (small-order, mixed-order and non-canonical keys and signatures) with no acceptance.
