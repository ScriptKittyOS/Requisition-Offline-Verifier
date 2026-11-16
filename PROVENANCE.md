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
| `verifier/verify_offline.py` | `bin/verify_offline.py` (requisition-aws) | `13f7729fcce3` | `813edaf013670a23d3303415eeb6b821ac475cb55c196a303096a33e8b752e24` | none |
| `verifier/lab-verify` | `bin/lab-verify` (requisition) | `61e49fea9938` | `95a5eff63b518a80a653d8a26ee16ebd86f2d1aed72e14f9e7037fbd1d56b097` (source file: `293cec59a879a89861473a9dbfff0ce45098532b8f194e963a06033de55abba3`) | one: see below |
| `verifier/verify_receipt.py` | `bench/holytrinity-v2/verifier/verify_receipt.py` (requisition) | `61e49fea9938` | `162c2e4d1ee0a129e2cc6899e638ad67847896eb3605ba3338089c8906213539` | none |
| `verifier/vendor/mldsa.py` | mldsa-py 1.0.1, `src/mldsa/mldsa.py` | upstream release | `0e8885d01ed76919f3152caa160f90949c03efc6a3748865aaf4beb2737c7a4a` | none |
| `verifier/vendor/LICENSE.mldsa` | mldsa-py 1.0.1, `LICENSE` | upstream release | `74b344a43288283ca7896b38d859bd6b91035110bb9c69856afbc60a01ff65e4` | none |

**The one change.** In its source tree `lab-verify` finds `verify_receipt.py` at
`../bench/holytrinity-v2/verifier/`. Here the two files sit in one directory, so the constant that holds
that path was changed. Nothing else differs. The complete difference from the source file:

```diff
155,161c155
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
(`bin/lab-verify`, `bin/vendor/mldsa.py`), and `lab-verify` carries
the project's reference `G-301` inside the two values of the signed `hands` label that it accepts.

The table named commits `e3f9e732d291` (requisition) and `b8571e3e057f` (requisition-aws) for the files of
2026-11-15, with SHA-256 `7962ad75…738f` (`lab-verify`), `9c0a4998…10ba` (`verify_receipt.py`) and `61d48b17…b184`
(`verify_offline.py`). The files of 2026-11-16 above replace them; "Changes to the verifier on 2026-11-16" below lists
each difference.

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

### Changes to the verifier from v0.1.0 to the files of 2026-11-15

Each line is a difference between a v0.1.0 file and the file of 2026-11-15, found by reading the difference of the two
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

### Changes to the verifier on 2026-11-16

Each line is a difference between the file of 2026-11-15 and the one in the table above, found by reading the
difference of the two files. A line says "measured" when it was checked by running the files, and "read in the code"
otherwise.

All three files

- Each starts with the `SPDX-License-Identifier: Apache-2.0` line and the copyright line (as a convenience; see the
  licence section below).
- Comments and docstrings were reworded; most internal references were removed or replaced by a description.
- Without the flags of the evaluation environment's log checkpoint check (below), `verify.sh` prints the same output as with the files of 2026-11-15, equal to
  `expected-output.txt`, and `tamper-test.sh` the same output (measured).
- `ed25519_verify` in `verify_receipt.py`, and `ed25519_key_acceptable` and `ed25519_signature_canonical` in
  `lab-verify`, are unchanged; `check_ed25519_material` in `lab-verify` differs only in its docstring (read in the
  code, by comparing the source text of each function).

The log checkpoint check of the evaluation environment, in all three files. The flags `--checkpoint`, `--inclusion-proof`, `--witness-policy`,
`--held-size`, `--held-root`, `--held-state`, `--write-held-state`, `--consistency-proof` and `--key-transition`
check a record against a checkpoint of the evaluation environment's log. `verifier/CHECKPOINTS.md` and
`CHECKPOINTS.md` state each check of the evaluation environment's log, each input and each refusal.

- `verify_receipt.py` judges the evaluation environment's checkpoint after the receipt's own signature verified. A refusal exits 5 with a
  `checkpoint_` code, and a pass prints the `log checkpoint:` lines of the evaluation environment's checkpoint after
  the receipt's verdict. The file of 2026-11-15 skipped
  these flags without a word: given `--checkpoint`, it answered exit 0 for a valid receipt and said nothing of the
  evaluation environment's log (measured on `checkpoint-vectors/records/main-1.json`).
- `lab-verify` hands the flags to `verify_receipt.py` on the Ed25519 path and passes its refusals through. On its
  exit 0 it requires the line `log checkpoint: all checks held: ...`, which says that every check of the evaluation
  environment's checkpoint held, else exit 5, `lab_verifier_unavailable` (read
  in the code). On the ML-DSA-87 path (a record of the evaluation environment whose own signature is ML-DSA-87) the
  flags are refused, exit 5, `lab_checkpoint_unchecked_mldsa87` (read in the code). A flag given twice is a usage error, exit 2 (measured). The file of 2026-11-15 refused the flags as unknown
  arguments, exit 2 (measured).
- `verify_offline.py` hands the flags to `lab-verify`, with the co-signature beside the record. A refusal of the
  evaluation environment's checkpoint ends `verdict: FAIL (the log checkpoint: <code>)`, exit 6; a pass adds a section 4 with the `log checkpoint:` lines
  and one sentence to the PASS line (measured over the 32 cases of `checkpoint-vectors/`, see below). A usage error
  that `lab-verify` reports for these inputs is exit 2 (read in the code). The file of 2026-11-15 refused the flags as
  a usage error, exit 2 (measured).

`verifier/lab-verify`

- The signed `hands` label of a record of the evaluation environment may carry either of two values, `one-person (G-301)` and `two-account, two-passkey
  (G-301)`; any other value is refused as before, exit 1, `lab_label_missing`, and the message lists the two values.
  A record signed with the second value must carry two distinct `sanctioners` and two distinct `approval_records`,
  else exit 1, `lab_hands_unsupported`; when it passes, its answer adds a line saying what that value rests on and
  that it is not re-derived here. A record that carries a `hands_evidence` member is refused, exit 1,
  `lab_hands_unsupported`. The file of 2026-11-15 refused every value but the first, exit 1, `lab_label_missing`.
  (Read in the code; both records here carry the first value, and their answers did not change.)
- The message of `lab_label_missing` no longer names an internal decision; it says that every lab record is signed
  with the four labels (read in the code).

`verifier/verify_offline.py`

- Its second encoder, `canonical_payload.v4`, which it does not use to verify a record, refuses the integer `-0` as
  `negative_zero` (read in the code).

## The evaluation environment's log checkpoint check: its documents, its test and its vectors

Added on 2026-11-16.

| Document on the evaluation environment's log checkpoint check | Source | Source commit | SHA-256 | Changes |
|---|---|---|---|---|
| `CHECKPOINTS.md` | `CHECKPOINTS.md` (requisition-aws) | `13f7729fcce3` | `5701a24e725d8bba31c458c6499b63b83983d5ea94a98c186acc1d86c68b02a3` | none |
| `verifier/CHECKPOINTS.md` | `bench/holytrinity-v2/verifier/CHECKPOINTS.md` (requisition) | `61e49fea9938` | `5a5645d8f31bcf2b724c0a6350b2fc77a2f123cb11a6f600693d7f64c9303039` | none |

The two documents are copied unchanged, so they name places in their source trees. Here:

- `bin/lab-verify` is `verifier/lab-verify`; requisition-aws's `bin/verify_offline.py` is `verifier/verify_offline.py`;
  `bench/holytrinity-v2/verifier/` is `verifier/`.
- For the evaluation environment's log, `verifier/CHECKPOINTS.md` also describes `verify_receipt.exs` and `verify_receipt_checkpoint.exs`, the Elixir
  verifier of the source tree, and `CHECKPOINTS.md` names `bin/verify_chain.py`; none of the three is in this
  repository.
- `lab/checkpoint-vectors/` of the Requisition repository, the evaluation environment's vectors, is
  `checkpoint-vectors/` here, without its provenance note.
  `verifier/CHECKPOINTS.md` says that folder of the evaluation environment's vectors holds 26 cases; at the source commit it holds 32, and so does
  `checkpoint-vectors/manifest.json` (measured). "The tests run all four verifiers" refers to the source tree's
  tests; here `checkpoint-test.sh` runs `verifier/verify_offline.py`, which runs the other two Python files, over the evaluation
  environment's vectors.

`checkpoint-test.sh`, which runs the check over the evaluation environment's vectors, was written for this
repository. It runs `verifier/verify_offline.py` with the checkpoint flags of each case of the evaluation environment
in `checkpoint-vectors/manifest.json` and compares the answer with the case's `expect`: exit 0 and the
PASS line's checkpoint sentence for `ok`, exit 6 and `verdict: FAIL (the log checkpoint: <code>)` for a refusal.

The vectors were made by the evaluation environment's own code, in one test run: the records by its signing path
under a development Ed25519 key whose seed is fixed, the checkpoints and the key change by its log, the witness
cosignatures by test witnesses written from the C2SP tlog-witness and tlog-cosignature specifications, and the
inclusion and consistency proofs by its read routes; the forked history by the same log rolled back and given other
records. Each negative case changes the producer's bytes in one stated way. The manifest's `expect` is the verdict
every offline verifier must give, and `lab_expect` the evaluation environment's own judgement; they differ in one
case, a policy naming an ML-DSA-44 witness, which the evaluation environment reads and these verifiers refuse by
name. None of these records is a 13 November record, and their key is not one of the AWS KMS keys of the
evaluation environment in `record/public-keys.json`. (Read in the source folder's provenance note.)

Each vector file of the evaluation environment is byte-equal to the file of the same name under `lab/checkpoint-vectors/` of requisition at
`61e49fea9938` (measured, by SHA-256):

| Vector file of the evaluation environment | Source path (requisition) | SHA-256 |
|---|---|---|
| `checkpoint-vectors/arguments.json` | `lab/checkpoint-vectors/arguments.json` | `af1566902a162074748d1b8901ab241e9191425177848f3dc6fd2beeaf3f1aa9` |
| `checkpoint-vectors/lab-keys.json` | `lab/checkpoint-vectors/lab-keys.json` | `8983c19a52187ab93b57937cfe1f120cefec07325bd1b0e953572a81e1307b46` |
| `checkpoint-vectors/manifest.json` | `lab/checkpoint-vectors/manifest.json` | `aa212eda0760238b338487f3b1b44d93d043873980e7ef4ba3323dd5fa04f2e5` |
| `checkpoint-vectors/notes/a.cosigned` | `lab/checkpoint-vectors/notes/a.cosigned` | `59b9e1c7aba6de98e4a200889c32542dbdac28688bb144cf225b6c795cfb6cb4` |
| `checkpoint-vectors/notes/a.new-key` | `lab/checkpoint-vectors/notes/a.new-key` | `becfad92d8293a6ed62894dde85f18cb92d9c4a5e4c8f9d9ccb29cdca3b32fe0` |
| `checkpoint-vectors/notes/b.cosignature-time-over-max` | `lab/checkpoint-vectors/notes/b.cosignature-time-over-max` | `ca5bd1ddbc1211ad5ef2b0d77077a903b8218af6352beb0f2611c4ccbc3a6ebf` |
| `checkpoint-vectors/notes/b.cosigned` | `lab/checkpoint-vectors/notes/b.cosigned` | `180eb8308a5753bbac3f4f005ae34a0764622b701a0400c2d6822c3bbffdda16` |
| `checkpoint-vectors/notes/b.no-blank-line` | `lab/checkpoint-vectors/notes/b.no-blank-line` | `ce7e171117b0a24aa4106e974a5e9dec4e4dd38791ea473dc3083a5f0cf71856` |
| `checkpoint-vectors/notes/b.one-witness` | `lab/checkpoint-vectors/notes/b.one-witness` | `1453a993531b38d08f660a1d4d89ee530e7aaf218b86c5a178116e1e11beaded` |
| `checkpoint-vectors/notes/b.one-witness-twice` | `lab/checkpoint-vectors/notes/b.one-witness-twice` | `4506f51faa56a4a1ef24d9653b2dadfadf3a811892005b524ebafb6fa655530b` |
| `checkpoint-vectors/notes/b.outsider-and-one` | `lab/checkpoint-vectors/notes/b.outsider-and-one` | `a37ce49a3b7b6dd7a758d8eb1da8c061a5972107074f90516d0b441bb9e37e84` |
| `checkpoint-vectors/notes/b.three-witnesses` | `lab/checkpoint-vectors/notes/b.three-witnesses` | `0a30dd63196d71371773359bc72d12c229c96642cfc46ae480dc557c88c52476` |
| `checkpoint-vectors/notes/b.witness-line-changed` | `lab/checkpoint-vectors/notes/b.witness-line-changed` | `95ad304d3cbf8fcf48afaf0d78d3a28b36e9168271847e558a565ae76701cd3a` |
| `checkpoint-vectors/notes/c.cosigned` | `lab/checkpoint-vectors/notes/c.cosigned` | `95d7793793a46b8b417bd1ba35d6064905f6eb6c41d3ec2ffc4f2f96d10e5634` |
| `checkpoint-vectors/notes/fork.cosigned` | `lab/checkpoint-vectors/notes/fork.cosigned` | `6fcae6133c7bb34cbfcc8a8c00a6b8d9b7cc6d3c3a4cf8c0b8cf92d0eb7c8a0c` |
| `checkpoint-vectors/notes/fork.new-key` | `lab/checkpoint-vectors/notes/fork.new-key` | `2f373ada394cc7ac35b403bfb44c72654f6ae99bcd721b9a24979014e1d56de6` |
| `checkpoint-vectors/notes/other-origin.log-note` | `lab/checkpoint-vectors/notes/other-origin.log-note` | `20a1bfac72832366d31ba0a707e150eda8e918899ef04d9e7a1692cacc0dfb44` |
| `checkpoint-vectors/notes/other-origin.relabelled` | `lab/checkpoint-vectors/notes/other-origin.relabelled` | `732c38b1c12670319c4c8d6127309d44dcc93551c071ddeefa92aa602d4ea451` |
| `checkpoint-vectors/policies/fork.policy` | `lab/checkpoint-vectors/policies/fork.policy` | `7e7d13c641d2c02b46f4a26f4478253dfa255c2830ecf4042be9ca5b70cff702` |
| `checkpoint-vectors/policies/main.policy` | `lab/checkpoint-vectors/policies/main.policy` | `b77748d05eddc8661f6a69b8810b1f7cc03ada0f74f8386d99c7a51547f45015` |
| `checkpoint-vectors/policies/mldsa44-witness.policy` | `lab/checkpoint-vectors/policies/mldsa44-witness.policy` | `bb69a219ed7caa9b08449e62a78e38ff182abc1a470c051165ade42dd9c6bbed` |
| `checkpoint-vectors/policies/wrong-log-key.policy` | `lab/checkpoint-vectors/policies/wrong-log-key.policy` | `09f3c7fdfd7b6e13730dac724c37d9e011db6820c296580e5116731793e28b5f` |
| `checkpoint-vectors/proofs/consistency-3-7.json` | `lab/checkpoint-vectors/proofs/consistency-3-7.json` | `f7261811454f1fdf5cb459245272d3cc2f3fddd6cb0f7ee68d4f4d044cc36d13` |
| `checkpoint-vectors/proofs/consistency-3-8.json` | `lab/checkpoint-vectors/proofs/consistency-3-8.json` | `39e779cdb6de4c1ceffd05bfa42d28faad2a4f9652874079220233ef8dd93699` |
| `checkpoint-vectors/proofs/consistency-7-8.json` | `lab/checkpoint-vectors/proofs/consistency-7-8.json` | `42897ae9c74d0184847f4ebd38c26dc9664b172123f565b9491443b20cf48d6b` |
| `checkpoint-vectors/proofs/consistency-fork-3-7.json` | `lab/checkpoint-vectors/proofs/consistency-fork-3-7.json` | `e7b89eccf62d58e0abb6c3d1c26f449f5d91bfbddf7b8f18065a4abfc85b4785` |
| `checkpoint-vectors/proofs/inclusion-fork-1-at-7.json` | `lab/checkpoint-vectors/proofs/inclusion-fork-1-at-7.json` | `cb4bb3f4b54fcff6eac8eda42c9f591636fc1268be5dca4b0d8ef88b665eb620` |
| `checkpoint-vectors/proofs/inclusion-main-1-at-3.json` | `lab/checkpoint-vectors/proofs/inclusion-main-1-at-3.json` | `d85d46de7180afd836489d243df9b6eb9ac5cb0e3e72272b83ee94ea0df317f7` |
| `checkpoint-vectors/proofs/inclusion-main-1-at-7.index-moved.json` | `lab/checkpoint-vectors/proofs/inclusion-main-1-at-7.index-moved.json` | `98189d99e37e6b7466f79d4445dccdab74790d3ece7b22b6a9ea03348d3c589d` |
| `checkpoint-vectors/proofs/inclusion-main-1-at-7.json` | `lab/checkpoint-vectors/proofs/inclusion-main-1-at-7.json` | `b7da59f7376b01a5dadc83760727a3f2ca2b0b7f5e1f8ae23c24d7686c8b95dc` |
| `checkpoint-vectors/proofs/inclusion-main-1-at-7.other-leaf-hash.json` | `lab/checkpoint-vectors/proofs/inclusion-main-1-at-7.other-leaf-hash.json` | `5acfdacea7060855f696e97cce84694d3dc378b8203afbfe1084a75410018c20` |
| `checkpoint-vectors/proofs/inclusion-main-1-at-7.size-changed.json` | `lab/checkpoint-vectors/proofs/inclusion-main-1-at-7.size-changed.json` | `173c9bc19b79b7361cb659adfad902ad158feda6edc441b290dda0388fd679eb` |
| `checkpoint-vectors/proofs/inclusion-main-1-at-7.truncated.json` | `lab/checkpoint-vectors/proofs/inclusion-main-1-at-7.truncated.json` | `48aa7b3bfa522046d667ce4a79079d169953b63a75e25af48302b5ba51f41ab2` |
| `checkpoint-vectors/proofs/inclusion-main-1-at-8.json` | `lab/checkpoint-vectors/proofs/inclusion-main-1-at-8.json` | `37f0128170e0cf78d74f97b5d8e5fca37b1827b520f8f94076998e6a63213f0e` |
| `checkpoint-vectors/proofs/inclusion-other-1.json` | `lab/checkpoint-vectors/proofs/inclusion-other-1.json` | `dc34cd4578f1ca8c2c05eb3b2dc699fa809b002f5a0bea060b2bb35a0eadf8cb` |
| `checkpoint-vectors/records/fork-1.json` | `lab/checkpoint-vectors/records/fork-1.json` | `3c76a5b5950026e8c9bd74e40af3a79b1e02754b2a0e5d71ad094f7dd56cb6eb` |
| `checkpoint-vectors/records/key-transition.endorsement-changed.json` | `lab/checkpoint-vectors/records/key-transition.endorsement-changed.json` | `dc17fbfbfce5ef85d1cb7e89accf88dc95ede6e910b605f7b1128791ece8bb3c` |
| `checkpoint-vectors/records/key-transition.json` | `lab/checkpoint-vectors/records/key-transition.json` | `d6785e582d2a73e09e23e9c67050fce51a5f124604509f5391173e4e4bd8ad1d` |
| `checkpoint-vectors/records/main-1.cosignature-not-base64.json` | `lab/checkpoint-vectors/records/main-1.cosignature-not-base64.json` | `6b244a95677b23ae92f6540c9fcdfc349bc8bef17895664cdd8d06737933f23d` |
| `checkpoint-vectors/records/main-1.json` | `lab/checkpoint-vectors/records/main-1.json` | `1907203dd2890d6417050e84bc0e337b6cf5aea1cb96af36eefb1b35b7bef670` |
| `checkpoint-vectors/records/main-2.json` | `lab/checkpoint-vectors/records/main-2.json` | `e737f54315381bbccb8d8d238bb7fb2c5ab32db9bdc841ad7d21396642273cf4` |
| `checkpoint-vectors/records/other-1.json` | `lab/checkpoint-vectors/records/other-1.json` | `8f3cbd15a8343f9be313442cc3d0ca61e8ee894be7a5ccd61cf2c901c3a4ba5e` |

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

Up to the change of licence below, no file from v0.1.0 changed except `README.md` (an `interop/` entry in the file list, a section "Other verifiers", a
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

For the files of 2026-11-15, measured on that date:

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

For the files of 2026-11-16 (the tables above), measured on that date:

- `sh verify.sh` exits 0 and its output equals `expected-output.txt`, on Python 3.11.15 and 3.12.3, in an empty
  environment (`env -i`).
- `sh tamper-test.sh` exits 0, with the same output as with the files of 2026-11-15.
- `sh checkpoint-test.sh` exits 0: 32 cases of the evaluation environment, 6 pass and 26 are refused by name, each as the manifest expects, on
  Python 3.11.15 and 3.12.3, with the same output on both.
- A system-call trace (`strace -f -e trace=network`) of `sh verify.sh`, and one of `sh checkpoint-test.sh` over the
  evaluation environment's vectors, shows no network system calls.
- `python3 -B -I tools/check-licence.py` passes.

## The licence from the next release (Apache License 2.0)

Releases up to and including v0.1.0 were published under the Requisition-Offline-Verifier Verification Licence 1.0,
and they stay under it: that text is `LICENSE` at the tag v0.1.0. From the next release, this repository is licensed
under the Apache License 2.0:

- `LICENSE` is the Apache License 2.0 text, 11,358 bytes, SHA-256
  `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`.
- `NOTICE` names the copyright holder and the NIST source of the ACVP vectors; `THIRD-PARTY.md` lists the files
  that keep their own licences. The Apache License does not require either file of this repository; they are kept
  so that the copyright holder and the third-party licences are stated in one place.
- Each source file written for this repository starts with an `SPDX-License-Identifier: Apache-2.0` line and the
  copyright line, as a convenience for readers and tools; the licence does not require them.
  `python3 -B -I tools/check-licence.py` checks the licence text, the NOTICE, those headers, and that the
  interop downloads are pinned by hash.
- The interop harnesses' downloads are pinned: `interop/verifiers/pyca-cryptography/requirements.txt` (pip, by
  SHA-256), `interop/verifiers/noble-post-quantum/package-lock.json` (npm, by SHA-512), and the Bouncy Castle jar by
  SHA-256 in `interop/run-all.sh`. Each harness's README says where its digest came from.

## Signed releases

The commits and release tags of this repository are signed with the OpenPGP key of Ayla Croft, fingerprint
`24FE 4F05 E3E8 EC26 1462  A0C7 82A6 7035 D628 7F15`. The public key is published independently at
`https://github.com/HackTuah.gpg`, Ayla Croft's GitHub account. Check a release with `git verify-tag <tag>`, and
check that the fingerprint git reports matches both the one above and the key at that address. A fingerprint read
only from this file or this repository does not show who signed it.
