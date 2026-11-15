# Other ML-DSA-87 verifiers

The record in `record/` carries two ML-DSA-87 signatures (FIPS 204), one over the statement and one over the
decision. `verify.sh` checks them with one library, the pure-Python mldsa-py in `verifier/vendor/`. This folder
lets you check the same two signatures with eight further programs, and runs all nine over the same 260 cases (Erlang/OTP over the 239 that have no context).

## What was measured

Each program below was run over `cases.tsv` (260 cases) on 2026-11-14. Every one reported no case in which its
answer differed from the expected answer.

| Verifier | Version | Language | Cases run | Result | Measured | Platform |
|---|---|---|---|---|---|---|
| mldsa-py | 1.0.1 | Python 3.12.3 | 260 | 0 disagree | 2026-11-14 | Linux x86-64 |
| pyca/cryptography | 50.0.2, on OpenSSL 4.0.3 | Python 3.12.3 | 260 | 0 disagree | 2026-11-14 | Linux x86-64 |
| Erlang/OTP `crypto` | OTP 28, on OpenSSL 3.5.9 | Erlang | 239 (21 not run) | 0 disagree | 2026-11-14 | Linux x86-64 |
| @noble/post-quantum | 0.7.1 | JavaScript, Node v22.23.2 | 260 | 0 disagree | 2026-11-14 | Linux x86-64 |
| Go `crypto/mldsa` | Go 1.27.4 | Go | 260 | 0 disagree | 2026-11-14 | Linux x86-64 |
| Bouncy Castle `bcprov-jdk18on` | 1.87 | Java 21.0.13.0.3 | 260 | 0 disagree | 2026-11-14 | Linux x86-64 |
| AWS-LC | 5.14.0 | C, gcc 13.3.0 | 260 | 0 disagree | 2026-11-14 | Linux x86-64 |
| wolfSSL | 5.9.4 | C, gcc 13.3.0 | 260 | 0 disagree | 2026-11-14 | Linux x86-64 |
| Botan | 3.14.1 | C++, g++ 13.3.0 | 260 | 0 disagree | 2026-11-14 | Linux x86-64 |

The exact result line of each program is in its folder, `verifiers/<name>/README.md`, with where to get the library
(and its SHA-256 where one was recorded), the commands that build and run it, and the line it should print.

## The cases

`cases.tsv` has 260 cases, one per line: case id, public key, signature, message, context, expected result
(1 means the signature must verify, 0 means it must not), in lower-case hex, `-` for empty. 76 cases expect 1.

- 4 from the record in this repository: the statement's ML-DSA-87 signature and the decision's, each as published
  (expected 1) and each with bit 0 of byte 100 of the signature flipped (expected 0). The bytes are the ones
  `verifier/verify_offline.py` checks: the `cosignature` member of `record/statement.json` and
  `record/decision.json`, the public key named by its `key_id` in `record/public-keys.json`, the UTF-8 bytes of
  `signed_payload` as the message, and the empty context.
- 15 from the NIST ACVP ML-DSA-sigVer test vectors (ML-DSA-87, external interface, pure): 3 valid, 12 invalid.
- 241 from the C2SP Wycheproof ML-DSA-87 verify test vectors: 71 valid, 170 invalid. Among them are malformed hint
  encodings, a repeated hint, wrong-length keys and signatures, and over-long contexts.

The two vector files, their provenance and their licences are in `vectors/`. `build-cases.py` derives `cases.tsv`
from `record/` and `vectors/` using only the Python standard library; `python3 -B interop/build-cases.py --check`
exits 0 when the committed `cases.tsv` equals what it derives and 1 when it does not. The SHA-256 of `cases.tsv` is
`be385c339c765ead8dfd68645d5116b873c806f6002e6a8df8fd6ed4e94a3f96`.

Contexts: 21 of the 260 cases have a non-empty context (14 ACVP, 7 Wycheproof); 5 of them have a context of 256
bytes, one over the 255-byte limit of FIPS 204, and all five expect rejection. 4 cases have a public key that is
one byte too short or too long, and 3 have a signature of the wrong length; all of these expect rejection.

## Which verifiers share code

- pyca/cryptography and Erlang/OTP `crypto` both call OpenSSL. They are one code base reached through two
  bindings. (The two result lines name the OpenSSL each ran on: 4.0.3 and 3.5.9.)
- AWS-LC is the library AWS names as the base of its post-quantum implementations. AWS's page on post-quantum
  cryptography (https://aws.amazon.com/security/post-quantum-cryptography) says: "At the foundation of these
  implementations is AWS-LC, our FIPS-140-3-validated cryptographic library". The record was signed with keys in AWS
  KMS (`PROVENANCE.md`). AWS-LC's result therefore adds no independence from the signer: it shows that a library from
  the same company as the signing service accepts the record. This folder does not say which library KMS uses internally.
- The others (mldsa-py, @noble/post-quantum, Go `crypto/mldsa`, Bouncy Castle, wolfSSL, Botan) are separate
  projects. This folder does not claim how much code, if any, they share with one another or with the libraries
  above.

This folder makes no claim that any of these libraries has been validated, certified or audited, and no count of
independent implementations. It records, for each program, whether its answers matched the expected
results on these cases when run as described.

## Limits

- Erlang/OTP's `crypto` interface takes no context, so the 21 cases that have a context are not run there (239
  are). Its result line says so.
- The wolfSSL and AWS-LC harnesses refuse a context over 255 bytes before calling the library (5 cases). In
  wolfSSL the context-length argument is one byte, so the library cannot be given such a context. For AWS-LC a run
  without the harness's own check also reported 0 disagreements, so AWS-LC itself rejected those 5 cases.
- One machine (Linux x86-64) and one build of each library. Other platforms, compilers, build options and library
  versions were not run.
- The 260 cases are all tests of verification. Signing, other parameter sets, pre-hashed signatures and the
  external-mu interface were not run.
- A case line ends at a line feed. A carriage return before it was accepted by six harnesses (mldsa-py, pyca/cryptography,
  Go, Bouncy Castle, AWS-LC, wolfSSL) and refused with exit 2 by three (Erlang/OTP, @noble/post-quantum, Botan);
  a carriage return followed by more text on the same line, or used alone as a line separator, was refused by all nine.
- The harnesses were written for this folder. They are short, and they are included so you can read them.
- Agreement on these cases is not a proof that a library is correct on other inputs.

## Run it yourself

Check that the cases are the ones the record and the vectors produce:

```
python3 -B interop/build-cases.py --check
```

Run every verifier you have set up:

```
interop/run-all.sh
```

`run-all.sh` finds each library through the environment variables named in its header and in the
`verifiers/<name>/README.md` files. It prints one line per verifier, prints `SKIPPED` and the reason for one it
cannot run, never downloads anything, and exits 0 only when every verifier that ran agreed on every case and at
least one ran. mldsa-py needs only `python3`, so a run with nothing set still runs it. A harness exits 1 and names
the case ids when its library disagrees with an expected result; a disagreement is a result to report, not an
error to work around.
