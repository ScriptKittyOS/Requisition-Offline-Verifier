# mldsa-py

- Library: mldsa-py 1.0.1, pure Python, the file this repository already uses to check the record
  (`verifier/vendor/mldsa.py`, SHA-256 `0e8885d01ed76919f3152caa160f90949c03efc6a3748865aaf4beb2737c7a4a`, pinned in
  `PROVENANCE.md`).
- Nothing to download or build. It needs only `python3`.
- The harness loads `verifier/vendor/mldsa.py` from this repository and prints the first 16 hex digits of its SHA-256.
  `-B` stops Python writing a bytecode cache; `-I` ignores the environment and the current directory.

Run, from the top of this repository:

```
python3 -B -I interop/verifiers/mldsa-py/verify.py interop/cases.tsv
```

Result measured 2026-11-14 (Python 3.12.3, Linux x86-64):

```
mldsa-py 1.0.1 (sha256 0e8885d01ed76919, Python 3.12.3): 260 cases, 0 disagree with the expected result []
```

## Exit status

0 when no case disagrees with its expected result; 1 when at least one does (the result line names the case ids);
2 on a bad command line or a malformed cases file. A line of `interop/cases.tsv` has six tab-separated fields: case
id, public key, signature, message, context, expected result (1 or 0), in lower-case hex with `-` for empty.
