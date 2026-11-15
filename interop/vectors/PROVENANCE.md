# ML-DSA-87 test vectors: where they come from

Both files were fetched 2026-11-09 from raw.githubusercontent.com at pinned commits. In this repository
they are read by `interop/build-cases.py`.

## `acvp_sigver_mldsa87_pure_external.json` (NIST ACVP, modified: a subset)

- Source: https://github.com/usnistgov/ACVP-Server, release **v1.1.0.43**, commit
  `975de31eb83d87039ec88934fdc47d8c312b892d`, file
  `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json`.
- Upstream file sha256: `47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437`.
- **Modified 2026-11-09:** kept only the test group whose `parameterSet` is `ML-DSA-87`,
  `signatureInterface` `external`, `preHash` `pure`, `externalMu` false (tgId 5, tcIds 61-75: 3 valid,
  12 invalid: modified message, commitment, hint, z), the form the record's ML-DSA-87 signatures use and
  `verifier/vendor/mldsa.py` exposes; dropped each test's `sk` (the verifier never needs a private key). Every other
  member is as published. File sha256 after the change:
  `768460682c2d81e101eeeefac12a0cfdb5d4712e0f718c2212bcfdf0a4a90522`.
- Not carried, with the reason: tgId 6 (HashML-DSA pre-hash: not the form the record uses), tgId 11
  (external mu) and tgId 12 (internal interface): the vendored module's public API takes a message and
  a context, not M' or mu.
- Licence: NIST-developed software notice, kept intact in `LICENSE.nist-acvp-server` as it asks. Source:
  the National Institute of Standards and Technology.

## `wycheproof_mldsa_87_verify_test.json` (C2SP Wycheproof, unmodified)

- Source: https://github.com/C2SP/wycheproof, commit `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`, file
  `testvectors_v1/mldsa_87_verify_test.json`, byte for byte.
- sha256: `54adffe10f6dad7941ffd97f77ad4e5c85cb3a54d44cf5ce1c95cb1757b9ba14`.
- 241 cases: 71 valid, 170 invalid, among them tcId 21 "signature with a repeated hint" (the class of
  CVE-2026-24850), tcIds 18-22 and 163-165/173 malformed hint encodings, 72 infinity-norm violations,
  tcIds 240-241 the missing-reduction pair, wrong key and signature lengths, and over-long contexts.
- Licence: Apache License 2.0, `LICENSE.wycheproof` (sha256
  `58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd`).
