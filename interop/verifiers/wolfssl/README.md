# wolfSSL

- Library: wolfSSL 5.9.4 (C), wolfCrypt ML-DSA (`wc_MlDsaKey_ImportPubRaw`, `wc_MlDsaKey_VerifyCtx`).
- Where to get it: the v5.9.4-stable release of https://github.com/wolfSSL/wolfssl , file
  `wolfssl-5.9.4-stable.tar.gz`, SHA-256 `7256bfc89b183a75183806c7debfa203443873b0b4a562e1b80d68e01b45ac57`.
- Measured with gcc 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), cmake 3.28.3, GNU Make 4.3, Linux x86-64.
- Limit: the context length argument of `wc_MlDsaKey_VerifyCtx` is one byte, so a context over 255 bytes cannot be
  passed. The harness refuses those before the call (5 of the 260 cases; all expect rejection); the library was not
  given the chance to refuse them.

Build and run, from the top of this repository. `WORK` is any empty folder; `WOLFSSL_TARBALL` is the downloaded file:

```
echo "7256bfc89b183a75183806c7debfa203443873b0b4a562e1b80d68e01b45ac57  $WOLFSSL_TARBALL" | sha256sum -c -
mkdir -p "$WORK/wolfssl/src" "$WORK/wolfssl/out"
tar -xzf "$WOLFSSL_TARBALL" -C "$WORK/wolfssl/src" --strip-components=1
cd "$WORK/wolfssl/out"
cmake -S ../src -B . -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DWOLFSSL_MLDSA=yes -DWOLFSSL_EXAMPLES=no \
  -DWOLFSSL_CRYPT_TESTS=no -DCMAKE_INSTALL_PREFIX="$WORK/wolfssl/install"
cmake --build . -j4 && cmake --install .
```

Then, from the top of this repository (`WOLFSSL_PREFIX` is `$WORK/wolfssl/install`):

```
interop/verifiers/wolfssl/compile.sh "$WOLFSSL_PREFIX" "$WORK/wolfssl-verify"
"$WORK/wolfssl-verify" interop/cases.tsv
```

Result measured 2026-11-14 (Linux x86-64):

```
wolfSSL 5.9.4: 260 cases, 0 disagree with the expected result []
```

## Exit status

0 when no case disagrees with its expected result; 1 when at least one does (the result line names the case ids);
2 on a bad command line or a malformed cases file. A line of `interop/cases.tsv` has six tab-separated fields: case
id, public key, signature, message, context, expected result (1 or 0), in lower-case hex with `-` for empty.
