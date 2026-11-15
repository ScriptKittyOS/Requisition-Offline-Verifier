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

Copied from two private source repositories at the commits below. The commits are in those repositories' main
history.

| File | Source path | Source commit | SHA-256 | Changes |
|---|---|---|---|---|
| `verifier/verify_offline.py` | `bin/verify_offline.py` (requisition-aws) | `b8571e3e057f` | `61d48b1704442975fe18ca32178ae1ef3032ea52390cd10204041830db2eb184` | none |
| `verifier/lab-verify` | `bin/lab-verify` (requisition) | `e3f9e732d291` | `7962ad753029b13720fd0f5c0b600d3af545a6c683b1365fa51580e73558738f` | one: see below |
| `verifier/verify_receipt.py` | `bench/holytrinity-v2/verifier/verify_receipt.py` (requisition) | `e3f9e732d291` | `9c0a49988cd5cbd81c629d9122335cc49d51baa35ff1a1c3e8315e5da40310ba` | none |
| `verifier/vendor/mldsa.py` | mldsa-py 1.0.1, `src/mldsa/mldsa.py` | upstream release | `0e8885d01ed76919f3152caa160f90949c03efc6a3748865aaf4beb2737c7a4a` | none |
| `verifier/vendor/LICENSE.mldsa` | mldsa-py 1.0.1, `LICENSE` | upstream release | `74b344a43288283ca7896b38d859bd6b91035110bb9c69856afbc60a01ff65e4` | none |

**The one change.** In its source tree `lab-verify` finds `verify_receipt.py` at
`../bench/holytrinity-v2/verifier/`. Here the two files sit in one directory, so the constant that holds
that path was changed. Nothing else differs. The complete difference from the source file:

```diff
138,144c138
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

Because the source files are otherwise unchanged, their comments and some output lines use the source trees' paths
(`bin/lab-verify`, `bin/vendor/mldsa.py`) and the project's internal reference numbers and work names (`G-…`, `REQ-…`, round and finding names).

### Source commits, corrected on 2026-11-15

The table of the v0.1.0 tag named commit `22c75da4729a` for `lab-verify` and `verify_receipt.py`. That commit is in a
working copy made for the change, and it is not in the history of the `requisition` repository (`git cat-file -t`
finds no such object there). The v0.1.0 bytes of the two files are in that repository's main history: `lab-verify`
(with its one path change undone) is `bin/lab-verify` at `1761669a`, and `verify_receipt.py` is the file at `b7d2a78e`
(compared byte for byte, both equal). The v0.1.0 table named `97a2fceeafc3` for `verify_offline.py`; that commit is in
the main history of the `requisition-aws` repository and the file at it has the SHA-256 the v0.1.0 table gives. The
tag itself is not edited.

The three files in the table above are the files of the two repositories' main history at the commits named there.
With them, `verify.sh` prints the same output as with the v0.1.0 files, and so does `tamper-test.sh`.

### Changes to the verifier since v0.1.0

Each line is a difference between a v0.1.0 file and the current one, found by reading the difference of the two
files. Each difference in what a file prints or answers was checked by running both files on the same input, except
where a line says it was read in the code. "Exit" is the exit status of the file named.

`lab-verify` runs `verify_receipt.py`, and `verify_offline.py` runs `lab-verify`, so a refusal added to
`verify_receipt.py` can change their answers too. For example, for a record whose key has `valid_from`
`2026-02-30T00:00:00Z`, `lab-verify` now exits 5 with `key_valid_from_unusable` (v0.1.0: exit 5 with `lab_dev_key`, its
answer for a record that passes) and `verify_offline.py` exits 3 (v0.1.0: exit 0).

`verifier/verify_receipt.py`

- An input file is refused (exit 2, `cannot read input`) when it is larger than 1 MiB, nests arrays and objects more
  than 64 deep, holds `NaN`, `Infinity`, a number beyond a double, an integer of more than 1024 characters or `-0e5` (a
  negative zero with an exponent and no fraction), has an unpaired surrogate in a string or a member name, or has an
  object that repeats a member name at any depth. v0.1.0 read these (exit 0 for an otherwise valid receipt), except an
  integer of more than 4,300 digits (exit 2) and deep nesting (1,000 levels on Python 3.11.15, 100,000 on 3.12.3), which
  ended in a stack trace (exit 1).
- Signed bytes that repeat a member name, nest more than 64 deep, or hold `NaN`, `Infinity`, a number beyond a double,
  `-0e5`, an integer of more than 1024 characters or an unpaired surrogate are not read: `TRUST NOT ESTABLISHED`, exit
  5, `signed_occurred_at_unreadable`, and the message names the reason. v0.1.0 verified such a receipt (exit 0),
  except an integer of more than 4,300 digits (exit 5, the same code) and deep nesting (3,000 levels on Python
  3.11.15, 100,000 on 3.12.3), which ended in a stack trace (exit 1).
- The message of `signed_occurred_at_unreadable` also says that the instant must be a real calendar instant; when the
  signed bytes are not a JSON object, or are not read, it says which.
- A timestamp that ends in a newline after the `Z` is refused: the signed `occurred_at`
  (`signed_occurred_at_unreadable`), a key's `valid_from` (`key_valid_from_unusable`) or `valid_to`
  (`key_valid_to_unreadable`), each exit 5. v0.1.0 accepted it.
- A timestamp that has the form but is not a real instant (month 13, day 00, 30 February, 31 November, hour 24, second
  60) is refused with the same codes. v0.1.0 accepted these. 29 February 2028 is accepted by both.
- A base64 value is decoded only in its padded standard form: a key file `public_key` written with an `=` after a
  complete group of four characters is not decoded and is answered `key_fingerprint_mismatch`; v0.1.0 decoded it (exit
  5 in both).
- A record whose `key_id` is the empty text matches no key file entry, even one listed under the empty text: exit 5,
  `registry_missing_key` (v0.1.0: exit 0).
- A float shown beside the signed bytes is compared by its sign as well: `-0.0` shown over a signed `0.0` is refused,
  exit 1, `displayed_field_mismatch` (v0.1.0: exit 0).
- A key file that is not a JSON object (a list, a string, a number, `true`, `null`) is answered exit 5,
  `registry_missing_key`; v0.1.0 ended in a stack trace (exit 1).
- For a key marked compromised (exit 6), a `status_changed_at` that is absent or not text is printed as "an unstated
  instant"; v0.1.0 printed `None` or the value as Python writes it.
- On exit 0, the note that the signature binds the receipt's position in its chain is printed only when the signed bytes
  carry both `sequence` and `previous_hash`; otherwise one line names what they do not carry. v0.1.0 printed the note
  for every receipt it verified.
- When the output stream cannot encode a character of a message (an ASCII locale with Python's UTF-8 mode off), the
  character is written as an escape and a valid receipt exits 0; v0.1.0 ended in a stack trace (exit 1).
- The input files are read as UTF-8 whatever the locale: in an ASCII locale with Python's UTF-8 mode off, a valid
  receipt whose file holds a non-ASCII character exits 0, where v0.1.0 refused it (exit 2, `cannot read input`).
- An exception that no check foresaw ends in exit 2 with one line naming its type, not in a stack trace (read in the
  code, the last lines of the file; not run).

`verifier/lab-verify`

- A ninth check, on both of its paths: a record whose signed metadata has no `act_hash_alg` member is refused (exit 1,
  `lab_act_hash_alg_absent`), and one whose `act_hash_alg` is not one of the three labels in `ACT_HASH_ALGS` (another
  text, a number, a list, null) is refused (exit 1, `lab_act_hash_alg_unknown`). v0.1.0 passed such records (exit 5,
  `lab_dev_key`, `lab_kms_key` or `lab_signature_unchecked_mldsa87`). A record under one of the three labels, and a
  CEASE record, which carries no label, are answered as before.
- A key file entry whose `algorithm` is a list or an object is refused, exit 1, `lab_key_algorithm_unknown`; v0.1.0
  ended in a stack trace (exit 1).
- With `--accept-signer`, a key file entry whose `signer` is a list or an object is refused, exit 5,
  `lab_signer_not_accepted`; v0.1.0 ended in a stack trace (exit 1).
- The refusal `lab_act_hash_absent` reads "the signed metadata binds no act hash."; v0.1.0 went on "only a lab
  statement or decision binds an act."
- On the Ed25519 path, signed bytes that repeat a member name, nest 65 deep, or hold `NaN`, `Infinity`, `1e400` or an
  integer of 1025 characters now get `verify_receipt.py`'s answer, passed through (exit 5,
  `signed_occurred_at_unreadable`), where v0.1.0 answered exit 1, `lab_signed_payload_unreadable`. Signed bytes that
  hold `-0e5` or an unpaired surrogate, which v0.1.0 passed (exit 5, `lab_dev_key` or `lab_kms_key`), get the same
  answer. On the ML-DSA-87 path these answers did not change.

`verifier/verify_offline.py`

- A record with no `act_hash_alg` member is reported `act_hash_alg: ABSENT (...)` instead of
  `act_hash_alg: MISMATCH (... signed None)`; in both versions the binding fails (exit 1). As in v0.1.0, the act hash
  is derived under `sha384+canonical_payload.v3` only, and any other value of `act_hash_alg` is a mismatch.
- In a record whose signed metadata carries a `verdict` (not an outcome record), a signed `metadata.code` that is
  neither text nor null adds the line `code: NOT TEXT (signed ...)` and fails the binding (exit 1). v0.1.0 ended in a
  stack trace (exit 1) for `true`, a non-zero number, a non-empty list or a non-empty object, and passed `0`, `false`,
  `[]` and `{}` (exit 0).
- A co-signature whose signed `cosign` member marks its key a lab KMS key (it says `"signer": "kms"` or has a
  `kms_key_arn`) passes only if the key is one: the key file entry and the `cosign` member both say signer `kms`, the
  key id is the lab KMS prefix for its algorithm followed by a resource id, and the signed `cosign.kms_key_arn` is a KMS
  key ARN ending in `key/<that resource id>`. Otherwise the record fails, exit 4, with one line naming the values.
  v0.1.0 passed these records (exit 0) unless `--accept-signer` refused the co-signing key (exit 4).
- The PASS line of a record signed by a lab KMS key names the co-signing key's signed `kms_key_arn` only beside a
  co-signature that passed the check above. v0.1.0 also named the `kms_key_arn` of a `cosign` member when no
  co-signature was present. A co-signing key the signed bytes name no KMS key for is named by its key id and its key
  file entry's `signer`; v0.1.0 counted it among "the LAB key(s) the key file pins as AWS KMS keys".
- When the key file requires post-quantum and no flag asks for it, the line reads
  `post-quantum REQUIRED (key file policy): met`; v0.1.0 printed `post-quantum REQUIRED (--require-pq): met` although
  the flag was not given.
- When post-quantum is required and not met, the reason says what was found: a co-signature announced as signed and not
  present ("stripped"); no `cosign.status`, no co-signature and no single ML-DSA-87 key file entry for the record's own
  key; a record that does not bind the arguments; or a signature, co-signature or key entry that does not check out.
  v0.1.0 said "the record carries no cosign member and no ML-DSA-87 signature" also of records that carry a cosign
  member or an ML-DSA-87 signature. The exits are the same.
- A signed `cosign.status` that is a list or an object, with post-quantum required and no co-signature present, is
  printed in the reason (exit 4); v0.1.0 ended in a stack trace (exit 1).
- With `--accept-signer`, a key file entry whose `signer` is a list or an object fails: the record's own ML-DSA-87 key
  with exit 3, a co-signing key with exit 4; v0.1.0 ended in a stack trace (exit 1).
- The file holds a second encoder, `canonical_payload.v4`, which it does not use to verify a record:
  `derivation_label` returns the v3 label for every record (read in the code).

All three files

- Comments and docstrings were reworded. The docstring of `ed25519_signature_canonical`
  in `lab-verify` names the `verify_receipt.py` of the published receipt-verification release r4, which accepts a
  non-canonical R. `verifier/verify_receipt.py` in this repository refuses such a signature (exit 1,
  `signature_invalid`).

## The interoperability folder (`interop/`)

Added after v0.1.0. Written for this repository: `interop/README.md`, `interop/build-cases.py`, `interop/run-all.sh`,
`interop/cases.tsv` (derived by `build-cases.py` from `record/` and `interop/vectors/`; SHA-256
`be385c339c765ead8dfd68645d5116b873c806f6002e6a8df8fd6ed4e94a3f96`), and everything under `interop/verifiers/`.
The harnesses call the libraries they test and contain no copy of them.

The test vectors are third-party files. Their sources, pinned commits and licences are in
`interop/vectors/PROVENANCE.md`.

| File | Source | SHA-256 | Changes |
|---|---|---|---|
| `interop/vectors/acvp_sigver_mldsa87_pure_external.json` | NIST ACVP-Server v1.1.0.43, ML-DSA-sigVer-FIPS204 | `768460682c2d81e101eeeefac12a0cfdb5d4712e0f718c2212bcfdf0a4a90522` | a subset of the upstream file, as described in `interop/vectors/PROVENANCE.md` |
| `interop/vectors/wycheproof_mldsa_87_verify_test.json` | C2SP Wycheproof, `testvectors_v1/mldsa_87_verify_test.json` | `54adffe10f6dad7941ffd97f77ad4e5c85cb3a54d44cf5ce1c95cb1757b9ba14` | none |
| `interop/vectors/LICENSE.nist-acvp-server` | NIST ACVP-Server | `7d1308ff19c82f712268ec64951db2fa0ed04b7ec6158b449842210ad79e3d85` | none |
| `interop/vectors/LICENSE.wycheproof` | C2SP Wycheproof | `58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd` | none |

`interop/vectors/PROVENANCE.md` is the provenance note of the vector files; it was reworded in four places for this repository: two
referred to files outside this repository, and two used a term not defined here.

No file from v0.1.0 changed except `README.md` (an `interop/` entry in the file list, a section "Other verifiers", a
licence line for the vectors, the description of Requisition worded as "an authority of record", and the paragraph on
`DEGRADED (lab)` narrowed to the two records here), this file, `SHA256SUMS`, the three files
`verifier/verify_offline.py`, `verifier/lab-verify` and `verifier/verify_receipt.py` (see "The verifier" above), and
`verifier/vendor/VENDORED.md` (one sentence: the two vector files are now in this repository).

## How the copy was checked

For the v0.1.0 copy, before that tag was published:

- `sh verify.sh` passes on Python 3.11.15 and 3.12.3, in an empty environment (`env -i`), with identical output.
- A system-call trace (`strace -f -e trace=network`) of `sh verify.sh` shows no network system calls.
- `sh tamper-test.sh` passes: the untouched copy verifies and each of the eight tampered copies is refused.
- The strict Ed25519 rules in `verify_receipt.py` and `lab-verify` were reviewed independently against 102
  adversarial inputs (small-order, mixed-order and non-canonical keys and signatures) with no acceptance.

For the files of 2026-11-15 (the table above), measured on that date:

- `sh verify.sh` exits 0 and prints the same output as with the v0.1.0 files, equal to `expected-output.txt`, on
  Python 3.11.15 and 3.12.3, in an empty environment (`env -i`).
- `sh tamper-test.sh` exits 0: the untouched copy verifies and each of the eight tampered copies is refused; its
  output equals the output with the v0.1.0 files.
- A system-call trace (`strace -f -e trace=network`) of `sh verify.sh` shows no network system calls.
- The 102 inputs of that review (4 valid signatures that must be accepted, 98 adversarial inputs that must be
  refused), given to `ed25519_verify` of `verifier/verify_receipt.py`: all 102 get the expected answer, 4 accepted and
  98 refused, on Python 3.11.15 and 3.12.3. The v0.1.0 file gives the same 102 answers. `ed25519_key_acceptable` and
  `ed25519_signature_canonical` of `verifier/lab-verify` answer the same on all 102 inputs as in v0.1.0. The inputs
  were given to these functions directly; the 95 of them that the review also ran through the command line were not
  run again.
