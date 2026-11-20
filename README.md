# Requisition offline verifier: two signed records of one approval, from an evaluation environment with Ed25519 and ML-DSA-87 keys in AWS KMS

This repository holds two signed records of one approval, a statement and a decision, and the program that verifies them. Anyone can run the verification on their own machine, offline, with one command.

The records come from a run on 13 November 2026 in Requisition's evaluation environment, in which an AI agent asked to send a refund. [Requisition](#about-requisition), an authority of record for agent actions, held the request until it was approved by two separate accounts, then signed its decision. Both approver accounts were operated by one person in this run, as the signed `hands` label of each record states: `"hands": "one-person (G-301)"`.

Each of the two records carries two signatures over the same bytes, both made inside AWS KMS keys of the evaluation environment: Ed25519 (RFC 8032) and ML-DSA-87 (FIPS 204), a post-quantum signature standard.

The evaluation environment is not part of a production release of Requisition. A production release refuses to start with the evaluation environment's settings, among them its AWS KMS keys, and it signs with Ed25519 alone. [What a pass proves, and what it does not](#what-a-pass-proves-and-what-it-does-not) states the limits exactly.

## Verify it

Requirements: Python 3.11 or newer and a POSIX shell. It was tested with Python 3.11.15 and 3.12.3 on Linux; other versions were not tested. From a copy of this repository there is nothing to install. No network access is used.

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

## Install

This verifier is not a package: it is the files of this repository. There are two ways to get them, and neither downloads and runs a script.

- **A copy of this repository.** There is nothing to install; run `sh verify.sh` as above.
- **The release's offline bundle**, for a machine without network access: `requisition-offline-verifier-<version>-offline.tar.gz`. Unpack it first (`tar -xzf requisition-offline-verifier-<version>-offline.tar.gz`, then `cd requisition-offline-verifier-<version>-offline`). It holds the release archive, its software bill of materials (CycloneDX) and a `SHA256SUMS` file. A digest inside the same bundle is not an anchor by itself, so anchor `SHA256SUMS` before you rely on it: check its detached signature `SHA256SUMS.asc` against the release key (see [Signed releases](PROVENANCE.md#signed-releases)), or compare its SHA-256 with the value published with the release. Then:

```
sha256sum -c SHA256SUMS
tar -xzf requisition-offline-verifier-<version>.tar.gz
cd requisition-offline-verifier-<version>
sha256sum -c SHA256SUMS
sh verify.sh
```

Three companion packages are published. None of them is needed to run this verifier.

| package | version | registry page | what it is |
|---|---|---|---|
| `requisition-aws` | 0.1.0 | PyPI: <https://pypi.org/project/requisition-aws/0.1.0/> | Python adapters for Requisition's evaluation environment and an offline check of its records |
| `requisition-ts` | 0.1.0 | npm: <https://www.npmjs.com/package/requisition-ts/v/0.1.0> | a TypeScript SDK and an MCP proxy for the same environment |
| `requisition_receipt_verifier` | 0.1.0 | Hex: <https://hex.pm/packages/requisition_receipt_verifier/0.1.0> | the Elixir receipt verifier, built from [`elixir/`](elixir/README.md) of this repository |

A registry page is not an anchor by itself. Compare what you download with the values below: they are in this repository, whose release tags are signed (see [Signed releases](PROVENANCE.md#signed-releases)).

**PyPI, by the file's SHA-256.** Download without installing, then compute the digest:

```
python3 -m pip download --no-deps requisition-aws==0.1.0
sha256sum requisition_aws-0.1.0-py3-none-any.whl
```

| file | SHA-256 |
|---|---|
| `requisition_aws-0.1.0-py3-none-any.whl` | `338d935a09b2776a089dfa3aaeb883eea29041bda529a6a58662d097cba696b3` |
| `requisition_aws-0.1.0.tar.gz` | `b0780f4ce034e195312df42af83db84e3152d5aff62728a3797ad3e9f67a51f5` |

To make pip refuse any other file, install with `python3 -m pip install --require-hashes -r requirements.txt`, where `requirements.txt` gives `--hash=sha256:<digest>` for this package and for each of its dependencies.

**npm, by the registry's `integrity` value.** npm compares the package file it downloads (the tarball) with that value, and a `package-lock.json` keeps it.

```
npm view requisition-ts@0.1.0 dist.integrity
```

Expected: `sha512-H+5Hsy2HvRnRaVI55vQdAT4RLFn4I1c9fX+Qzl20aKqV8MGiurVCeBaJ8cacVsV9ztwp7PyxhonJlu7EfWg7cA==`. To compute it from the file: `npm pack requisition-ts@0.1.0`, then `openssl dgst -sha512 -binary requisition-ts-0.1.0.tgz | openssl base64 -A` prints the part after `sha512-`. The SHA-256 of that file is `9215d8db2f0539df7423ce69ffa539519f6566b927dc2a24cd409ff86080389c`.

**Hex, by the checksum in `mix.lock` and the signed tag.** After `mix deps.get`, the last value of the package's entry in `mix.lock` is the SHA-256 of the downloaded package file, and Mix refuses a later download that does not match it. Expected: `87606c42b077d7b7305742fb58a72e5251b4b89e61a7471d560cd8f8536fb226`. `mix hex.package fetch requisition_receipt_verifier 0.1.0` downloads the same file without adding a dependency, for `sha256sum`. Each of the 11 files inside the package is, byte for byte, the file of the same name under `elixir/` at this repository's signed tag `v0.2.0`.

## What happened in the run

1. An AI agent asked, through a tool call, to refund 12.50 USD to a customer account, reason "duplicate charge". The exact arguments are in [`record/arguments.json`](record/arguments.json).
2. The request was approved by two separate accounts, neither of them the requester's.
3. Requisition signed a **statement** ([`record/statement.json`](record/statement.json), sequence 15). It fixes the hash of the action, a digest of what the approvers were shown, and the identifiers of the two approver accounts.
4. Requisition signed a **decision** ([`record/decision.json`](record/decision.json), sequence 16, verdict `allow`). It names the statement it follows and carries the same action hash.

## What the verifier checks

`verify.sh` runs the same three checks on the statement and on the decision. Each check judges one record: its authenticity and its binding to the action.

**1. The record is bound to this exact action.** The verifier recomputes a SHA-384 hash over a canonical form of the arguments and the action type, and compares it with the hash inside the signed bytes. It does the same for the digest of what the approvers were shown. An approval for "refund 12.50" cannot be presented as an approval for "refund 12.51".

**2. The Ed25519 signature is valid.** The signature and the record hash are checked against the Ed25519 public key in [`record/public-keys.json`](record/public-keys.json). The check is stricter than the bare RFC 8032 equation. It refuses:

- a non-canonical encoding of the public key or of R,
- a public key or R of small order,
- a public key outside the prime-order subgroup,
- S not below the group order.

The bare equation accepts some inputs it should not. Under the identity public key, for example, a signature can be forged for any message. The negative tests include that case.

**3. The ML-DSA-87 signature is valid.** A second signature over the same bytes is checked against the ML-DSA-87 public key in the key file (pure ML-DSA, empty context string). `--require-pq` makes a missing or invalid post-quantum signature a failure. `--accept-signer kms` refuses a record whose key entry is not marked as a KMS key.

As `verify.sh` runs it, the verifier reads three inputs and nothing else: the record, the arguments, and the public key file. Check 4 below adds the inputs it names. The verifier does not read the system clock.

**4. A log checkpoint of the evaluation environment, when you ask for one.** `verify.sh` does not run this check, and this repository holds no checkpoint of the evaluation environment for the two records above.

Given the flags `--checkpoint`, `--inclusion-proof` and `--witness-policy`, and optionally the tree size you hold, `verify_offline.py` also checks what the transparency log of the evaluation environment says of a record, after the record's own signature has verified:

- the record is included, by an RFC 9162 inclusion proof, under a checkpoint of the evaluation environment's log that the log key your policy names signed and that the witnesses your policy names cosigned, meeting its quorum;
- a checkpoint larger than the tree size you hold is shown, by an RFC 9162 consistency proof, to extend your tree;
- a checkpoint smaller than the tree size you hold, or of that size with another root, is refused.

A pass of this check shows that the record is in the evaluation environment's log at the checkpoint's tree size, and that this tree is an append-only extension of the tree you hold. It does not show that the checkpoint is the newest the evaluation environment's log has made, that the action ran, or anything about another record.

In the evaluation environment, a consistency proof covers only the tree you hold and the checkpoint given, and cannot show that another party was shown a different history; witness cosignatures are what can make that detectable, only for witness keys you configure yourself, at a threshold you choose, and as far as those witnesses are independent of the log. A cosignature of the evaluation environment shows what a key signed, never who holds the key.

If you keep the tree size you hold in a held-state file (`--held-state`), the evaluation environment's checkpoint is compared with that file and the check holds only as far as the file does: a lost or reset file compares the next checkpoint with nothing, and a file restored from a backup, copied from an older machine or written by someone else compares it with that older or chosen state. The file carries no signature or checksum of its own.

A refused checkpoint of the evaluation environment is named by its code, and `verify_offline.py` then ends with `verdict: FAIL (the log checkpoint: <code>)` and exit status 6. Not checked, in the evaluation environment: ML-DSA-44 witness cosignatures and a record whose own signature is ML-DSA-87 (both refused by name), the age of a checkpoint, and who runs a witness.

Each check of the evaluation environment's log, each input, every refusal code and what is not checked are stated in [`verifier/CHECKPOINTS.md`](verifier/CHECKPOINTS.md); what `verify_offline.py` adds to them is in [`CHECKPOINTS.md`](CHECKPOINTS.md). Both are unchanged copies from their source trees, so they name paths there; [`PROVENANCE.md`](PROVENANCE.md) maps those paths to this repository and states what differs.

To run the check on inputs made by the evaluation environment's own code, run `sh checkpoint-test.sh`. It runs `verify_offline.py` with these flags over the 39 cases in [`checkpoint-vectors/`](checkpoint-vectors/manifest.json) and compares each answer with the one the case's manifest entry expects: 6 cases pass and 33 are refused, each by its code. It then gives the check 138 inputs of another form, made from four passing cases: each JSON file flag given a file that holds a bare JSON value (`false`, `null`, `0`, `""`, `[]` and four more); a proof's `hash`, its `leaf_hash`, the record's `cosignature` or the `signature` of a cosignature object written as `null`, `false`, `true`, `0`, `""`, `[]` or `{}`, or left out; and a co-signature beside the record (`--cosignature`, or the member beside the record in an answer) holding a bare JSON value, with and without the checkpoint flags of the evaluation environment. Each is refused (a held-state file of that form is a usage error), except a member left out and the empty text as the co-signature member, which pass. The last line is `RESULT: PASS (39 cases: 6 pass, 33 refused by name, each as expected; 17 runs with a held-state file; 138 runs with an input of another form, each as expected)`. The vectors were made in a test run of the evaluation environment, under a development key and with test witnesses; they are not the 13 November records, and their key is not one of the AWS KMS keys of the evaluation environment named below. Each negative case changes the producer's bytes in one stated way. [`PROVENANCE.md`](PROVENANCE.md) says where they come from.

### About `DEGRADED (lab)` in the output

The Ed25519 check prints `DEGRADED (lab)` and exits with code 5 for both records here, although both are valid. That is deliberate: this tool does not report full trust for a key that is not anchored in a trust root. The outer verifier expects exactly that answer for this profile and reports `verdict: PASS` when all three checks hold, and not otherwise. With the flags of check 4 it also requires that check to hold.

## What a pass proves, and what it does not

A pass proves that:

- each record is bound to exactly the arguments and action type in `record/arguments.json`;
- the Ed25519 signature and the ML-DSA-87 signature on each record are valid, over the same bytes, under the two public keys in `record/public-keys.json` that the key file marks as AWS KMS keys of the evaluation environment;
- the records have not changed since they were signed.

Every pass prints this sentence after the verdict:

> A pass shows these bytes were signed under the key you supplied. It is not permission to act. Whether an action may run is decided by the issuing system when it runs.

An expired decision is still a valid record. The verifier reports the deadline a record signs as history, with the time as the record signs it: `This decision allowed execution until <time>.` for a decision that allowed, and `This statement was valid until <time>.` for a statement. A record that is neither has no such line. It compares no time unless you give one: `--at YYYY-MM-DDTHH:MM:SSZ` adds one line saying whether the signed window was open or closed at that instant. The exit status never depends on it. An argument a verifier does not take is a usage error (exit status 2), never skipped: a mistyped `--at` cannot pass in silence. The same record presented twice passes twice, with the same lines: refusing a second use is the work of the issuing system, not of a verifier. To run these cases on the two records here, run `sh pass-test.sh`; its last line is `RESULT: PASS (every case as expected)`. The rule and every line a pass can end with are stated in [`elixir/VERDICTS.md`](elixir/VERDICTS.md), section "What a pass says".

A pass does not prove the following, and this repository does not claim it.

- **The keys are evaluation keys, not a trust root.** Each entry of the key file is marked `"profile": "lab"`. You are trusting this repository to give you the right key file. A production deployment anchors its keys in a trust root that the relying party controls; that is not shown here.
- **Key custody is asserted, not verified.** The key file says the two private keys, keys of the evaluation environment, are held in AWS KMS and cannot be exported. An offline check cannot confirm where a private key lives.
- **The two approvals were not made by two independent persons.** Both approver accounts were operated by one person in this run. The signed bytes of each record say so, in the `hands` label quoted in the second paragraph of this page. What the run shows is that the action was held until two distinct approver accounts had approved it.
- **Nothing proves the action was carried out.** The records are a statement and a decision. A pass says nothing about what happened after the decision.
- **Signed times are not compared with the current time.** The statement carries `occurred_at`, `iat`, `nbf` and `exp`; the decision carries `occurred_at`, `decided_at`, `not_after` and `exec_not_after`. The verifier checks that each key was valid at the record's signed `occurred_at`; it does not check whether a record has since expired, and a time given with `--at` is reported and never changes the verdict. These are historical records.
- **One record is judged at a time.** A pass says nothing about other records of the same environment: whether a later record exists, or whether a record was withheld.
- **The server is not public.** You can verify the signed output of the run. You cannot reproduce the run.

## Keys

Two AWS KMS keys of the evaluation environment, in `us-east-2`, signed both records.

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
| `metadata.kms_key_arn`, `metadata.cosign` | The AWS KMS keys of the evaluation environment that the record says signed it |
| `metadata.hands` | The hands label; its signed value is quoted in the second paragraph of this page |
| `metadata.profile` | `lab`: the evaluation key profile |
| `sequence`, `previous_hash` | Position in the environment's append-only record chain. The statement's `previous_hash` points to an earlier record that is not published here; the decision's points to the statement |
| `metadata.principal`, `caller_id`, `grant_id`, `request_id`, `chain_scope` | Identifiers internal to the evaluation environment |

## Repository contents

```
verify.sh              the one command
tamper-test.sh         negative tests
checkpoint-test.sh     check 4 over the evaluation environment's checkpoint vectors
pass-test.sh           what a pass says: the fixed sentence, the signed deadline, a time given with --at
expected-output.txt    the output of verify.sh
record/
  arguments.json       the arguments of the action
  statement.json       the signed statement
  decision.json        the signed decision
  public-keys.json     the public key file
verifier/
  verify_offline.py    binds the record to the arguments; checks the ML-DSA-87 signature; runs lab-verify
  lab-verify           checks the record's kind, labels and key entry; runs verify_receipt.py
  verify_receipt.py    checks the Ed25519 signature and the record hash; check 4
  CHECKPOINTS.md       check 4: each check, input and refusal, and what is not checked
  vendor/mldsa.py      third-party ML-DSA (FIPS 204) verification, unmodified
CHECKPOINTS.md         check 4: what verify_offline.py adds
checkpoint-vectors/    39 cases for check 4: records, checkpoints, proofs, policies, and the manifest
interop/
  README.md            what was measured with nine ML-DSA-87 verifiers, and what it does not show
  cases.tsv            260 cases built from the record and two sets of test vectors
  build-cases.py       derives cases.tsv; --check compares it with the committed file
  run-all.sh           runs every verifier it finds
  verifiers/           one folder per verifier: the harness and how to build and run it
  vectors/             the two test-vector files, their provenance and licences
elixir/                the Elixir receipt verifier, verify_receipt.exs, as the source of a Hex package
tools/
  check-licence.py     checks the licence, the NOTICE, the source headers and the interop download pins
  check-stands-alone.py  checks that no file points at a private source tree, at one machine or at internal workflow,
                       and that the page says who operated the approver accounts, as the record's signed label does
PROVENANCE.md          where every file came from, with digests
SHA256SUMS             SHA-256 of every file
LICENSE                Apache License 2.0
NOTICE                 the copyright holder and the source of the NIST test vectors
THIRD-PARTY.md         the files that keep their own licences
```

The verifier uses the Python standard library and one vendored file, [`verifier/vendor/mldsa.py`](verifier/vendor/mldsa.py): mldsa-py 1.0.1 by Filippo Valsorda, pure Python, licensed CC0-1.0 OR 0BSD, copied unmodified. `verify_offline.py` refuses to load it unless its SHA-256 equals the pinned value. Its origin, digests and the test vectors it is checked against are in [`verifier/vendor/VENDORED.md`](verifier/vendor/VENDORED.md).

Tested with Python 3.11.15 and 3.12.3 on Linux. A system-call trace of `verify.sh` shows no network calls.

## Other verifiers

`verify.sh` checks the ML-DSA-87 signatures with one library, mldsa-py. The folder [`interop/`](interop/README.md) holds a case file built from this record and from two sets of public test vectors, and a harness for each of nine ML-DSA-87 verifiers: mldsa-py, pyca/cryptography, Erlang/OTP `crypto`, @noble/post-quantum, Go `crypto/mldsa`, Bouncy Castle, AWS-LC, wolfSSL and Botan. [`interop/README.md`](interop/README.md) records that in runs on 14 November 2026 each reported no disagreement with the expected result on the cases it ran, and gives the versions, the commands to repeat the runs, which of these libraries share code, and what the runs do not show.

## About Requisition

Requisition is an authority of record for what AI agents and other automated actors are allowed to do. A consequential action is held until the approver accounts it requires have approved it, and the statements and decisions Requisition signs can be verified by a third party without access to the system that produced them. This repository shows that last property.

An approval record for a consequential action may need to be relied on for many years. A record whose signature could be forged later is a record that could be rewritten later. That is the reason for the second, post-quantum signature on the records here, which Requisition adds in its evaluation environment.

The Requisition server is not open source. This verifier and these records are published so that the verification can be checked independently.

## Correction (2026-11-19)

The message of the tag `v0.1.0`, and the title of this page at that tag, said "two-person approval". The record does not show that. It shows two approver accounts, and one person operated both of them in this run; the signed bytes of each record say so: `"hands": "one-person (G-301)"`. The page at `v0.1.0` said this among the things a pass does not prove. The page at `v0.2.0` left that statement out; this page states it in its second paragraph and again among the things a pass does not prove. The published tags are not changed.

## Licence

From this release, the files of this repository that are its own are licensed under the [Apache License 2.0](LICENSE), copyright Sudo Apt Holdings LLC (Script Kitty OS & Labs); see [`NOTICE`](NOTICE).

Earlier releases keep the licence they were published under: v0.1.0 is under the Requisition-Offline-Verifier Verification Licence 1.0.

The vendored ML-DSA library keeps its own licence: [`verifier/vendor/LICENSE.mldsa`](verifier/vendor/LICENSE.mldsa).

The test vectors in `interop/vectors/` keep their own licences: [`LICENSE.nist-acvp-server`](interop/vectors/LICENSE.nist-acvp-server) for the NIST ACVP file and [`LICENSE.wycheproof`](interop/vectors/LICENSE.wycheproof) for the Wycheproof file. [`THIRD-PARTY.md`](THIRD-PARTY.md) lists the files that keep their own licences.

The release tag v0.1.0 is signed; [Signed releases](PROVENANCE.md#signed-releases) says how to check a release tag and which key signs it.

## Reporting a problem

If verification fails on an unmodified copy, or you find an input that this verifier accepts and should refuse, please open an issue in this repository.
