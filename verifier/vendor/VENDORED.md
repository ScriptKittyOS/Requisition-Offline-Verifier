# Vendored file

## `mldsa.py`: ML-DSA (FIPS 204) signature verification, pure Python

| | |
|---|---|
| what | `src/mldsa/mldsa.py` of mldsa-py, copied byte for byte, unmodified |
| author | Filippo Valsorda |
| upstream | https://github.com/FiloSottile/mldsa-py (PyPI project `mldsa`, https://pypi.org/project/mldsa/) |
| version | **1.0.1** (uploaded to PyPI 2026-07-26) |
| downloaded from | https://files.pythonhosted.org/packages/ee/12/47c2ce5d1c133fbdb50d24c8fc10cd7a5f4000a6f57888565514051a97fb/mldsa-1.0.1-py3-none-any.whl (fetched 2026-11-09) |
| wheel sha256 | `cad0a75124c5a6f4c1efe0e013039e9b0a1a86a9bb8ec5a75d6cf71a45ce08f9` (equals PyPI's published digest) |
| sdist sha256 | `005a296d138448d9210a1f36bdc3190d30a19595f1bbf2b92aa537049d797a31` (`mldsa-1.0.1.tar.gz`; its `src/mldsa/mldsa.py` is byte-identical to the wheel's) |
| **file sha256** | **`0e8885d01ed76919f3152caa160f90949c03efc6a3748865aaf4beb2737c7a4a`** |
| licence | CC0-1.0 OR 0BSD (the file's own header; PyPI `License-Expression`). `LICENSE.mldsa` beside this file is the upstream 0BSD `LICENSE`. |
| dependencies | none beyond the Python standard library (`hashlib.shake_128`, `hashlib.shake_256`, `dataclasses`, `enum`, `sys`, `typing`) |
| what it does | verification only; it holds no signing code and no key generation |

**How it is loaded.** It is never imported by name. `verifier/verify_offline.py` (`load_mldsa`) reads the
file by path, refuses it unless its SHA-256 equals the pinned value above, then executes it as a module.

**What it was checked against** in the source tree this file was copied from. The tests and vectors are
not part of this repository.

- NIST ACVP-Server `ML-DSA-sigVer-FIPS204/internalProjection.json` at release v1.1.0.43 (commit
  `975de31eb83d87039ec88934fdc47d8c312b892d`): the ML-DSA-87 pure external-interface group (tgId 5,
  15 cases).
- C2SP Wycheproof `testvectors_v1/mldsa_87_verify_test.json` at commit
  `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9` (241 cases), including tcId 21, "signature with a repeated
  hint".
- A differential against two other implementations: the `cryptography` package's ML-DSA-87 over
  OpenSSL 4.0.3, and Erlang/OTP 28 `:crypto` over OpenSSL 3.5.9.

To check the copy yourself: `sha256sum verifier/vendor/mldsa.py` and compare with the file sha256 above,
or compare the file with `src/mldsa/mldsa.py` in the upstream 1.0.1 release.
