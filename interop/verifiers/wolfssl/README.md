# wolfSSL

- Library: wolfSSL 5.9.4 (C), wolfCrypt ML-DSA (`wc_MlDsaKey_ImportPubRaw`, `wc_MlDsaKey_VerifyCtx`).
- Where to get it: the source archive of tag v5.9.4-stable,
  https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.9.4-stable.tar.gz , saved as
  `wolfssl-5.9.4-stable.tar.gz`, SHA-256 `7256bfc89b183a75183806c7debfa203443873b0b4a562e1b80d68e01b45ac57`.
  GitHub generates this archive on request; if GitHub regenerates it, its SHA-256 can differ from the one recorded here.
- Measured with gcc 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), cmake 3.28.3, GNU Make 4.3, Linux x86-64.
- Limit: the context length argument of `wc_MlDsaKey_VerifyCtx` is one byte, so a context over 255 bytes cannot be
  passed. The harness refuses those before the call (5 of the 260 cases; all expect rejection); the library was not
  given the chance to refuse them.

Build and run, from the top of this repository. `WORK` is any empty folder, given as an absolute path; `WOLFSSL_TARBALL` is the downloaded file:

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
2 when the run is not valid and no result line is printed: a wrong number of arguments, a cases file that cannot be
read, a line that is not six tab-separated fields, a field that is not hex (or `-`), an expected result other than 0 or 1,
or a cases file with no case in it. Only a case that was parsed and given to the library can agree or disagree.
A line of `interop/cases.tsv` has six tab-separated fields: case id, public key, signature, message, context, expected
result (1 or 0), in lower-case hex with `-` for empty.
