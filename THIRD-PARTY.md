# Third-party files

This repository is licensed under the Apache License 2.0 (`LICENSE`, `NOTICE`). The files below are not its own
work. Each keeps its own licence and carries no header of this repository.

| file | what it is | licence | licence text |
|---|---|---|---|
| `verifier/vendor/mldsa.py` | mldsa-py 1.0.1 by Filippo Valsorda, `src/mldsa/mldsa.py`, byte for byte (`verifier/vendor/VENDORED.md`) | CC0-1.0 OR 0BSD | the file's own header; `verifier/vendor/LICENSE.mldsa` |
| `interop/vectors/wycheproof_mldsa_87_verify_test.json` | C2SP Wycheproof test vectors, byte for byte (`interop/vectors/PROVENANCE.md`) | Apache-2.0 | `interop/vectors/LICENSE.wycheproof` |
| `interop/vectors/acvp_sigver_mldsa87_pure_external.json` | NIST ACVP-Server v1.1.0.43 test vectors, a subset (`interop/vectors/PROVENANCE.md`) | NIST-developed software notice | `interop/vectors/LICENSE.nist-acvp-server` |

The interop harnesses in `interop/verifiers/` call libraries you download yourself; no copy of any of them is in this
repository. Each harness's README names the library, its version, its digest and where that digest came from.
