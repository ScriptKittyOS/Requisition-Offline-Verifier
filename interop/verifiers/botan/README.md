# Botan

- Library: Botan 3.14.1 (C++), `Botan::Dilithium_PublicKey` with `DilithiumMode::ML_DSA_8x7` and `Botan::PK_Verifier`;
  the context is set with `PK_Signature_Options::with_context`.
- Where to get it: the Botan 3.14.1 source release from the project's download page, https://botan.randombit.net/ ,
  file `Botan-3.14.1.tar.xz`, SHA-256 `5b85cba0f014d344eb8e9919aee0a3bdc31e16acb05816410025be9bee1e0930`.
- Measured with g++ 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), GNU Make 4.3, Python 3.12.3 (for Botan's
  `configure.py`), Linux x86-64.
- Contexts: all 21 cases with a context are passed to the library, including the 5 over 255 bytes. The harness
  counts an exception thrown by the library as a refusal.

Build and run, from the top of this repository. `WORK` is any empty folder; `BOTAN_TARBALL` is the downloaded file:

```
echo "5b85cba0f014d344eb8e9919aee0a3bdc31e16acb05816410025be9bee1e0930  $BOTAN_TARBALL" | sha256sum -c -
mkdir -p "$WORK/botan/src" "$WORK/botan/out"
tar -xJf "$BOTAN_TARBALL" -C "$WORK/botan/src" --strip-components=1
cd "$WORK/botan/out"
python3 -I ../src/configure.py --minimized-build --enable-modules=ml_dsa,system_rng --disable-shared-library \
  --build-targets=static --without-documentation --no-install-python-module --with-build-dir="$WORK/botan/out" \
  --prefix="$WORK/botan/install" --build-tool=make --cc-bin=g++
make -j4 libs && make install
```

Then, from the top of this repository (`BOTAN_PREFIX` is `$WORK/botan/install`):

```
interop/verifiers/botan/compile.sh "$BOTAN_PREFIX" "$WORK/botan-verify"
"$WORK/botan-verify" interop/cases.tsv
```

Result measured 2026-11-14 (Linux x86-64):

```
Botan 3.14.1: 260 cases, 0 disagree with the expected result []
```

## Exit status

0 when no case disagrees with its expected result; 1 when at least one does (the result line names the case ids);
2 when the run is not valid and no result line is printed: a wrong number of arguments, a cases file that cannot be
read, a line that is not six tab-separated fields, a field that is not hex (or `-`), an expected result other than 0 or 1,
or a cases file with no case in it. Only a case that was parsed and given to the library can agree or disagree.
A line of `interop/cases.tsv` has six tab-separated fields: case id, public key, signature, message, context, expected
result (1 or 0), in lower-case hex with `-` for empty.
A line with no characters is skipped; a line of only spaces or tabs is not, and ends the run with exit 2.
