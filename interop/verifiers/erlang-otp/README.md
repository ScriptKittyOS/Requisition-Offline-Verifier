# Erlang/OTP

- Library: the `crypto` application of Erlang/OTP 28 (`crypto:verify(mldsa87, none, Message, Signature, PublicKey)`),
  which calls OpenSSL. The measured build was OTP 28.5.0.8 linked to OpenSSL 3.5.9 (29 Sep 2026).
  Measured: run with an Erlang whose `crypto` was linked to OpenSSL 3.0.13 (30 Jan 2024), the harness found no
  `mldsa87`, exited 3 and said so on standard error; it does not count the cases as disagreements.
- Where to get it: Erlang/OTP source releases are at https://www.erlang.org/ . Build or install OTP 28 so that its
  `crypto` application uses OpenSSL 3.5 or later. No checksum was recorded for the measured OTP
  build; the result line reports the OTP release and the OpenSSL version it runs on.
- This library and pyca/cryptography both call OpenSSL: see `interop/README.md`.
- Limit: `crypto:verify/5` has no context argument, so only the 239 cases with the empty context are run. The 21
  cases that have a context are counted as not run, and the line says so.

Run, from the top of this repository. `OTP_ESCRIPT` is the `escript` program of that OTP:

```
$OTP_ESCRIPT interop/verifiers/erlang-otp/verify.escript interop/cases.tsv
```

Result measured 2026-11-14 (Linux x86-64):

```
Erlang/OTP 28 :crypto on OpenSSL 3.5.9 29 Sep 2026: 239 cases with the empty context, 0 disagree with the expected result []; 21 cases with a context not run (no context argument)
```

Exit status: 0 when no case that ran disagrees, 1 when one does, 2 on a bad command line, 3 when this Erlang has no
ML-DSA-87. A line of `interop/cases.tsv` has six tab-separated fields: case id, public key, signature, message,
context, expected result (1 or 0), in lower-case hex with `-` for empty.

Exit status: 0 when no case that ran disagrees, 1 when one does, 2 on a bad command line, 3 when this Erlang has no
ML-DSA-87. A line of `interop/cases.tsv` has six tab-separated fields: case id, public key, signature, message,
context, expected result (1 or 0), in lower-case hex with `-` for empty.

## Exit status

0 when no case disagrees with its expected result; 1 when at least one does (the result line names the case ids);
2 on a bad command line or a malformed cases file. A line of `interop/cases.tsv` has six tab-separated fields: case
id, public key, signature, message, context, expected result (1 or 0), in lower-case hex with `-` for empty.
