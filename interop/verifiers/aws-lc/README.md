# AWS-LC

- Library: AWS-LC 5.14.0 (C), `EVP_PKEY_pqdsa_new_raw_public_key(NID_MLDSA87, ...)`, `EVP_DigestVerify`; the
  context is set with `EVP_PKEY_CTX_set1_signature_context_string`.
- Where to get it: the source archive of tag v5.14.0,
  https://github.com/aws/aws-lc/archive/refs/tags/v5.14.0.tar.gz , saved as `aws-lc-5.14.0.tar.gz`, SHA-256
  `8895a9d2434e875e009e652a1015f9c2c275261634c7132253ca5aa60d266888` (release page
  https://github.com/aws/aws-lc/releases/tag/v5.14.0). GitHub generates this archive on request; if GitHub
  regenerates it, its SHA-256 can differ from the one recorded here.
- Where the hash came from: it was computed over the archive downloaded on 2026-11-14 for the measured run. The
  project's release, as read that day, lists no SHA-256 for this generated archive, so the digest shows only that your
  archive is the one that was measured.
- Measured with gcc 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), cmake 3.28.3, GNU Make 4.3, Linux x86-64.
- Limit: the harness refuses a context longer than 255 bytes before calling the library (5 of the 260 cases; all
  expect rejection). Without that check the harness also printed 0 disagreements (measured 2026-11-14), so the
  library itself rejected those 5 cases.

Build and run, from the top of this repository. `WORK` is any empty folder, given as an absolute path; `AWSLC_TARBALL` is the saved file:

```
echo "8895a9d2434e875e009e652a1015f9c2c275261634c7132253ca5aa60d266888  $AWSLC_TARBALL" | sha256sum -c -
mkdir -p "$WORK/aws-lc/src" "$WORK/aws-lc/out"
tar -xzf "$AWSLC_TARBALL" -C "$WORK/aws-lc/src" --strip-components=1
cd "$WORK/aws-lc/out"
cmake -S ../src -B . -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DBUILD_LIBSSL=OFF -DBUILD_TOOL=OFF \
  -DDISABLE_GO=ON -DENABLE_SOURCE_MODIFICATION=OFF -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX="$WORK/aws-lc/install"
cmake --build . --target crypto -j4 && cmake --install .
```

Then, from the top of this repository (`AWSLC_PREFIX` is `$WORK/aws-lc/install`):

```
interop/verifiers/aws-lc/compile.sh "$AWSLC_PREFIX" "$WORK/aws-lc-verify"
"$WORK/aws-lc-verify" interop/cases.tsv
```

Result measured 2026-11-14 (Linux x86-64):

```
AWS-LC 5.14.0: 260 cases, 0 disagree with the expected result []
```

## Exit status

0 when no case disagrees with its expected result; 1 when at least one does (the result line names the case ids);
2 when the run is not valid and no result line is printed: a wrong number of arguments, a cases file that cannot be
read, a line that is not six tab-separated fields, a field that is not hex (or `-`), an expected result other than 0 or 1,
or a cases file with no case in it. Only a case that was parsed can agree or disagree; the 5 cases with a context
over 255 bytes are refused by the harness itself (see Limit above).
A line of `interop/cases.tsv` has six tab-separated fields: case id, public key, signature, message, context, expected
result (1 or 0), in lower-case hex with `-` for empty.
A line with no characters is skipped; a line of only spaces or tabs is not, and ends the run with exit 2.
