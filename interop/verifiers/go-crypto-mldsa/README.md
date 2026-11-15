# Go standard library, crypto/mldsa

- Library: `crypto/mldsa` of the Go standard library, Go 1.27.4 (`mldsa.NewPublicKey`, `mldsa.Verify`).
- Where to get it: the Go download page, https://go.dev/dl/ , file `go1.27.4.linux-amd64.tar.gz`,
  SHA-256 `7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840`. Unpack it; `GO_BIN` is its `bin/go`.
- The harness has no dependencies outside the standard library, so no module download is needed.

Run, from the top of this repository. The environment variables stop Go downloading anything and keep its caches
out of this repository; `CACHE` is any empty folder:

```
cd interop/verifiers/go-crypto-mldsa
GOTOOLCHAIN=local GOPROXY=off GOCACHE="$CACHE/gocache" GOPATH="$CACHE/gopath" "$GO_BIN" run . ../../cases.tsv
```

Result measured 2026-11-14 (Linux x86-64):

```
Go crypto/mldsa (go1.27.4): 260 cases, 0 disagree with the expected result []
```

## Exit status

0 when no case disagrees with its expected result; 1 when at least one does (the result line names the case ids);
2 when the run is not valid and no result line is printed: a wrong number of arguments, a cases file that cannot be
read, a line that is not six tab-separated fields, a field that is not hex (or `-`), an expected result other than 0 or 1,
or a cases file with no case in it. Only a case that was parsed and given to the library can agree or disagree.
A line of `interop/cases.tsv` has six tab-separated fields: case id, public key, signature, message, context, expected
result (1 or 0), in lower-case hex with `-` for empty.
A line with no characters is skipped; a line of only spaces or tabs is not, and ends the run with exit 2.

`go run` reports any non-zero exit of the program as exit status 1 and prints `exit status N` on standard error;
build with `go build` to see the program's own exit status.
