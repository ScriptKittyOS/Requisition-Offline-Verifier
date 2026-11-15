# pyca/cryptography

- Library: pyca/cryptography 50.0.2, its ML-DSA-87 interface (`cryptography.hazmat.primitives.asymmetric.mldsa`).
  The measured installation used OpenSSL 4.0.3 (29 Sep 2026), as the result line reports.
- Where to get it: the `cryptography` project on PyPI, version 50.0.2 (`pip install cryptography==50.0.2` into a
  virtual environment). Check that the installed package reports the version in the result line. The harness
  prints the version and OpenSSL it ran on, so a different installation is visible in the output.
- This library and Erlang/OTP both call OpenSSL: see `interop/README.md`.

Run, from the top of this repository. `PYCA_PYTHON` is the Python program of an environment in which the package is
installed:

```
$PYCA_PYTHON -B -I interop/verifiers/pyca-cryptography/verify.py interop/cases.tsv
```

Result measured 2026-11-14 (Linux x86-64):

```
pyca/cryptography 50.0.2 on OpenSSL 4.0.3 29 Sep 2026: 260 cases, 0 disagree with the expected result []
```

## Exit status

0 when no case disagrees with its expected result; 1 when at least one does (the result line names the case ids);
2 on a bad command line or a malformed cases file. A line of `interop/cases.tsv` has six tab-separated fields: case
id, public key, signature, message, context, expected result (1 or 0), in lower-case hex with `-` for empty.
