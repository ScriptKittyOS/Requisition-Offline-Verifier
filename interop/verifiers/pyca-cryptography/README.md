# pyca/cryptography

- Library: pyca/cryptography 50.0.2, its ML-DSA-87 interface (`cryptography.hazmat.primitives.asymmetric.mldsa`).
  The measured installation used OpenSSL 4.0.3 (29 Sep 2026), as the result line reports.
- Where to get it: the `cryptography` project on PyPI, version 50.0.2, with `cffi` 2.1.1 and `pycparser` 3.12, each
  pinned by version and SHA-256 in `requirements.txt` here. Install them into a new virtual environment
  (`WORK` is any empty folder); pip refuses any file whose SHA-256 is not listed:

  ```
  python3 -m venv "$WORK/pyca"
  "$WORK/pyca/bin/pip" install --require-hashes --only-binary=:all: -r interop/verifiers/pyca-cryptography/requirements.txt
  ```

  `PYCA_PYTHON` is then `$WORK/pyca/bin/python`. The harness prints the version and OpenSSL it ran on, so a
  different installation is visible in the output.
- Where the hashes came from: the SHA-256 digests PyPI's index lists for each file of those three versions, copied
  from a lock file made from that index. PyPI serves the files and the digests over the same HTTPS connection, so
  the digests show that a file is the one PyPI listed, not who built it.
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
2 when the run is not valid and no result line is printed: a wrong number of arguments, a cases file that cannot be
read, a line that is not six tab-separated fields, a field that is not hex (or `-`), an expected result other than 0 or 1,
or a cases file with no case in it. Only a case that was parsed and given to the library can agree or disagree.
A line of `interop/cases.tsv` has six tab-separated fields: case id, public key, signature, message, context, expected
result (1 or 0), in lower-case hex with `-` for empty.
A line with no characters is skipped; a line of only spaces or tabs is not, and ends the run with exit 2.
