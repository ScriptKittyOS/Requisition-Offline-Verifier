# Requisition offline verifier: a two-person approval, signed in AWS KMS with Ed25519 and ML-DSA-87

This repository holds one signed approval record and the program that verifies it. Anyone can run the verification on their own machine, offline, with one command.

The record comes from a run on 13 November 2026 in which an AI agent asked to send a refund. [Requisition](#about-requisition), a control plane for agent actions, held the request until two approvers had approved it, then signed its decision. Each signed record carries two signatures over the same bytes, both made inside AWS KMS:

- **Ed25519** (RFC 8032), and
- **ML-DSA-87** (FIPS 204), the post-quantum signature standard.

This is a proof of concept from an evaluation environment. [What a pass proves, and what it does not](#what-a-pass-proves-and-what-it-does-not) states the limits exactly.

## Verify it

Requirements: Python 3.11 or newer and a POSIX shell. Nothing to install. No network access is used.

```
sh verify.sh
```

The last line is `RESULT: PASS (both records verify)` and the exit status is 0. The full output should equal [`expected-output.txt`](expected-output.txt):

```
sh verify.sh | diff - expected-output.txt && echo identical
```

To see verification fail, run the negative tests. Each one copies the folder to a temporary directory, changes one thing, and expects a refusal:

```
sh tamper-test.sh
```

| Change | Result |
|---|---|
| Refund amount changed by one minor unit | Refused: the recomputed action hash no longer equals the signed one |
| One bit flipped in an Ed25519 signature | Refused: `signature_invalid` |
| One bit flipped in the ML-DSA-87 signature | Refused: ML-DSA-87 signature invalid |
| One character changed in the signed payload | Refused: the record hash no longer matches |
| Ed25519 public key replaced by another valid key | Refused: `signature_invalid` |
| Ed25519 public key replaced by the identity point, with a signature forged to match | Refused: `lab_key_not_prime_order` |
| ML-DSA-87 co-signature removed | Refused: the post-quantum signature is required |

To check that the files are the ones published here:

```
sha256sum -c SHA256SUMS
```

On macOS use `shasum -a 256 -c SHA256SUMS`.

## What happened in the run

1. An agent built with Strands Agents, running on a model in Amazon Bedrock, called a refund tool through Amazon Bedrock AgentCore Gateway: 12.50 USD to a customer account, reason "duplicate charge". The exact arguments are in [`record/arguments.json`](record/arguments.json).
2. Requisition held the call. The agent was told the action was awaiting approval, and the tool did not run.
3. Requisition signed a **statement** ([`record/statement.json`](record/statement.json), sequence 15). It fixes the hash of the action, a digest of what the approvers were shown, and the identifiers of the two approvers.
4. Two approver accounts, neither of them the requester, approved.
5. Requisition signed a **decision** ([`record/decision.json`](record/decision.json), sequence 16, verdict `allow`). It names the statement it follows and carries the same action hash.
6. The agent's next call for the same action ran once. The refund tool is a stub: no money moved.

## What the verifier checks

`verify.sh` runs the same three checks on the statement and on the decision.

**1. The record is bound to this exact action.** The verifier recomputes a SHA-384 hash over a canonical form of the arguments and the action type, and compares it with the hash inside the signed bytes. It does the same for the digest of what the approvers were shown. An approval for "refund 12.50" cannot be presented as an approval for "refund 12.51".

**2. The Ed25519 signature is valid.** The signature and the record hash are checked against the Ed25519 public key in [`record/public-keys.json`](record/public-keys.json). The check is stricter than the bare RFC 8032 equation. It refuses:

- a non-canonical encoding of the public key or of R,
- a public key or R of small order,
- a public key outside the prime-order subgroup,
- S not below the group order.

The bare equation accepts some inputs it should not. Under the identity public key, for example, a signature can be forged for any message. The negative tests include that case.

**3. The ML-DSA-87 signature is valid.** A second signature over the same bytes is checked against the ML-DSA-87 public key in the key file (pure ML-DSA, empty context string). `--require-pq` makes a missing or invalid post-quantum signature a failure. `--accept-signer kms` refuses a record whose key entry is not marked as a KMS key.

The verifier reads three inputs and nothing else: the record, the arguments, and the public key file. It does not read the system clock.

### About `DEGRADED (lab)` in the output

The Ed25519 check prints `DEGRADED (lab)` and exits with code 5 for every record signed under the evaluation key profile, including a valid one. That is deliberate: this tool does not report full trust for a key that is not anchored in a trust root. The outer verifier expects exactly that answer for this profile and reports `verdict: PASS` only when all three checks hold.

## What a pass proves, and what it does not

A pass proves that:

- each record is bound to exactly the arguments and action type in `record/arguments.json`;
- the Ed25519 signature and the ML-DSA-87 signature on each record are valid, over the same bytes, under the two KMS public keys in `record/public-keys.json`;
- the records have not changed since they were signed.

A pass does not prove the following, and this repository does not claim it.

- **The keys are evaluation keys, not a trust root.** The key file is marked `"profile": "lab"`. You are trusting this repository to give you the right key file. A production deployment anchors its keys in a trust root that the relying party controls; that is not shown here.
- **Key custody is asserted, not verified.** The key file says the two private keys are held in AWS KMS and cannot be exported. An offline check cannot confirm where a private key lives.
- **The two approvals were not made by two independent people.** Both approver accounts were operated by the author for this run. The signed bytes say so themselves: `"hands": "one-person (G-301)"`. What the run shows is that the control held the action until two distinct approver accounts had approved it.
- **Nothing proves the action was carried out.** The record is the decision. The refund tool was a stub.
- **Signed times are not compared with the current time.** The records carry `occurred_at`, `not_after` and `exec_not_after`. The verifier checks that each key was valid at the record's signed time; it does not check whether a record has since expired. This is a historical record.
- **The server is not public.** You can verify the signed output of the run. You cannot reproduce the run.

## Keys

Two keys in AWS KMS (`us-east-2`) signed both records. The account that holds them is used only for this public demonstration.

| | Ed25519 | ML-DSA-87 |
|---|---|---|
| KMS key spec | `ECC_NIST_EDWARDS25519` | `ML_DSA_87` |
| KMS signing algorithm | `ED25519_SHA_512` | `ML_DSA_SHAKE_256` |
| KMS message type | `RAW` | `RAW` |
| KMS key id | `303190ba-5445-49ec-9d8c-95b804b8c5cf` | `fd9cf1e7-608c-4f34-b5fe-cdf4cc37620d` |
| Public key length | 32 bytes | 2,592 bytes |
| Signature length | 64 bytes | 4,627 bytes |
| SHA-256 of the raw public key | `0e04c89cf177db8eb5db4d89dd6fbb89dd6d0ddbf08cc69c8131e91e65da210c` | `f28a4da4a0657c6dbc0a1558055ed8992f58dace0478492841ba86342893c71c` |
| SHA-256 of the SPKI DER returned by `GetPublicKey` | `54a22d4cc38d8b696fa65c4768dae955607ace1ff41d55096d47ff246e5fd9f2` | `30b2e060162cf4e0df25cd50b3d3168151f79a60d01d4a56a3e50954efbeac29` |

The full key ARNs, including the account id, appear inside the signed bytes of each record and in the key file. They are public on purpose.

The key file also lists two development keys of the evaluation environment (`"signer": "dev"`). They signed nothing in this repository, and `--accept-signer kms` refuses any record that names them.

## Reading the records

Each record file has two members: the Ed25519-signed envelope (`statement` or `decision`) and the ML-DSA-87 envelope (`cosignature`). Both envelopes carry the same `signed_payload`, a JSON string, and its SHA-256 as `receipt_hash`.

Fields in the signed payload that a reader may ask about:

| Field | Meaning |
|---|---|
| `metadata.act_hash`, `act_hash_alg` | The SHA-384 hash that binds the record to the action, and the name of the canonical form it was computed over |
| `metadata.display_digest` (statement), `display_projection_digest` (decision) | Digest of what the approvers were shown |
| `metadata.sanctioners` | Identifiers of the two approver accounts |
| `metadata.verdict` | The decision: `allow` |
| `metadata.statement_id` (decision) | The `receipt_hash` of the statement this decision follows |
| `metadata.kms_key_arn`, `metadata.cosign` | The KMS keys the record says signed it |
| `metadata.hands` | `one-person (G-301)`: both approver accounts were operated by one person. `G-301` is the project's reference for that limit |
| `metadata.profile` | `lab`: the evaluation key profile |
| `sequence`, `previous_hash` | Position in the environment's append-only record chain. The statement's `previous_hash` points to an earlier record that is not published here; the decision's points to the statement |
| `metadata.principal`, `caller_id`, `grant_id`, `request_id`, `chain_scope` | Identifiers internal to the evaluation environment. They identify no person |

## Repository contents

```
verify.sh              the one command
tamper-test.sh         negative tests
expected-output.txt    the output of verify.sh
record/
  arguments.json       the arguments of the action
  statement.json       the signed statement
  decision.json        the signed decision
  public-keys.json     the public key file
verifier/
  verify_offline.py    binds the record to the arguments; checks the ML-DSA-87 signature; runs lab-verify
  lab-verify           checks the record's kind, labels and key entry; runs verify_receipt.py
  verify_receipt.py    checks the Ed25519 signature and the record hash
  vendor/mldsa.py      third-party ML-DSA (FIPS 204) verification, unmodified
PROVENANCE.md          where every file came from, with digests
SHA256SUMS             SHA-256 of every file
LICENSE                Requisition-Offline-Verifier Verification Licence 1.0
```

The verifier uses the Python standard library and one vendored file, [`verifier/vendor/mldsa.py`](verifier/vendor/mldsa.py): mldsa-py 1.0.1 by Filippo Valsorda, pure Python, licensed CC0-1.0 OR 0BSD, copied unmodified. `verify_offline.py` refuses to load it unless its SHA-256 equals the pinned value. Its origin, digests and the test vectors it is checked against are in [`verifier/vendor/VENDORED.md`](verifier/vendor/VENDORED.md).

Tested with Python 3.11.15 and 3.12.3 on Linux. A system-call trace of `verify.sh` shows no network calls.

## About Requisition

Requisition is a control plane for what AI agents and other automated actors are allowed to do. A consequential action is held until the people who must approve it have approved it, and every decision is recorded in a form that a third party can verify without access to the system that produced it. This repository shows that last property.

An approval record for a consequential action may need to be relied on for many years. A record whose signature could be forged later is a record that could be rewritten later, which is the reason for the second, post-quantum signature.

The Requisition server is not open source. This verifier and these records are published so that the verification can be checked independently.

## Licence

[Requisition-Offline-Verifier Verification Licence 1.0](LICENSE). In short: you may read everything here, run the verifier and the negative tests, run the unmodified verifier on other Requisition records, and publish what you find. Redistribution, modified versions, building the materials into a product, and training a model on them need written permission. The licence text governs; this summary does not.

The vendored ML-DSA library keeps its own licence: [`verifier/vendor/LICENSE.mldsa`](verifier/vendor/LICENSE.mldsa).

Releases are tagged and signed. `git verify-tag v0.1.0` checks the signature; the licence gives the key fingerprint.

## Reporting a problem

If verification fails on an unmodified copy, or you find an input that this verifier accepts and should refuse, please open an issue in this repository.
