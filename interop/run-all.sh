#!/bin/sh
# Runs every verifier whose tool it finds over interop/cases.tsv and prints one line each.
# Tools are found through the environment variables named in interop/verifiers/*/README.md:
#   PYCA_PYTHON     a Python 3 with pyca/cryptography (with ML-DSA support) installed
#   OTP_ESCRIPT     the escript program of an Erlang/OTP 28 built on OpenSSL 3.5 or later
#   NOBLE_DIR       a folder holding package.json and node_modules/@noble/post-quantum   (and `node` on PATH)
#   GO_BIN          the go program of Go 1.27 or later
#   BC_JAR          a bcprov-jdk18on jar, version 1.87 or later                            (and `java` 21 on PATH)
#   AWSLC_PREFIX, WOLFSSL_PREFIX, BOTAN_PREFIX   the install folder of a build of the library
#   AWSLC_VERIFY, WOLFSSL_VERIFY, BOTAN_VERIFY   (instead of a prefix) a harness already compiled by the
#                                                verifier's compile.sh
# The mldsa-py verifier needs only python3.
# INTEROP_CASES   a different cases file (default: interop/cases.tsv)
# INTEROP_BUILD   a folder for compiled harnesses and caches (default: a new temporary folder, removed at the end)
# Nothing is downloaded. Exit 0 only when every verifier that ran agreed on every case and at least one ran.
here=$(cd "$(dirname "$0")" && pwd)
cases=${INTEROP_CASES:-$here/cases.tsv}
if [ -n "${INTEROP_BUILD:-}" ]; then
  build=$INTEROP_BUILD; mkdir -p "$build"; made=
else
  build=$(mktemp -d); made=1
fi
trap '[ -z "$made" ] || rm -r "$build"' EXIT
ran=0; bad=0
log="$build/run-all.stderr"

# run NAME COMMAND...: the command's stdout is the verifier's result line
run() {
  name=$1; shift
  line=$("$@" 2>"$log"); code=$?
  case $code in
    0) ran=$((ran + 1)); printf '%s\n' "$line" ;;
    1) ran=$((ran + 1)); bad=$((bad + 1)); printf '%s\n' "$line" ;;
    *) ran=$((ran + 1)); bad=$((bad + 1)); printf '%s: FAILED to run (exit %s): %s\n' "$name" "$code" "$(tail -n 1 "$log")" ;;
  esac
}
skip() { printf '%s: SKIPPED, %s\n' "$1" "$2"; }

# C and C++ harnesses: use a compiled one, or compile from the library's install folder
cverifier() { # name  PREFIXVAR VERIFYVAR
  name=$1; pre=$(eval "printf %s \"\${$2:-}\""); bin=$(eval "printf %s \"\${$3:-}\"")
  if [ -n "$bin" ]; then
    [ -x "$bin" ] || { skip "$name" "$3 is set but $bin is not an executable file"; return; }
  elif [ -n "$pre" ]; then
    bin=$build/$name-verify
    if ! "$here/verifiers/$name/compile.sh" "$pre" "$bin" >"$log" 2>&1; then
      skip "$name" "the harness did not compile against $2 (see interop/verifiers/$name/README.md)"; return
    fi
  else
    skip "$name" "neither $2 nor $3 is set"; return
  fi
  run "$name" "$bin" "$cases"
}

run mldsa-py python3 -B -I "$here/verifiers/mldsa-py/verify.py" "$cases"

if [ -n "${PYCA_PYTHON:-}" ] && [ -x "$PYCA_PYTHON" ]; then
  run pyca-cryptography "$PYCA_PYTHON" -B -I "$here/verifiers/pyca-cryptography/verify.py" "$cases"
else skip pyca-cryptography "PYCA_PYTHON is not set to a Python program"; fi

if [ -n "${OTP_ESCRIPT:-}" ] && [ -x "$OTP_ESCRIPT" ]; then
  run erlang-otp "$OTP_ESCRIPT" "$here/verifiers/erlang-otp/verify.escript" "$cases"
else skip erlang-otp "OTP_ESCRIPT is not set to an escript program"; fi

if [ -n "${NOBLE_DIR:-}" ] && [ -f "$NOBLE_DIR/package.json" ] && command -v node >/dev/null 2>&1; then
  run noble-post-quantum node "$here/verifiers/noble-post-quantum/verify.mjs" "$cases" "$NOBLE_DIR"
else skip noble-post-quantum "NOBLE_DIR is not set to a folder with a package.json, or node is not on PATH"; fi

if [ -n "${GO_BIN:-}" ] && [ -x "$GO_BIN" ]; then
  export GOTOOLCHAIN=local GOPROXY=off GOCACHE="$build/gocache" GOPATH="$build/gopath"
  run go-crypto-mldsa sh -c 'cd "$1" && exec "$2" run . "$3"' sh "$here/verifiers/go-crypto-mldsa" "$GO_BIN" "$cases"
else skip go-crypto-mldsa "GO_BIN is not set to a go program"; fi

if [ -n "${BC_JAR:-}" ] && [ -f "$BC_JAR" ] && command -v java >/dev/null 2>&1; then
  bcv=$(basename "$BC_JAR" .jar | sed 's/^bcprov-[a-z0-9]*-//')
  run bouncy-castle java -cp "$BC_JAR" "$here/verifiers/bouncy-castle/BcVerify.java" "$cases" "$bcv"
else skip bouncy-castle "BC_JAR is not set to a jar file, or java is not on PATH"; fi

cverifier aws-lc AWSLC_PREFIX AWSLC_VERIFY
cverifier wolfssl WOLFSSL_PREFIX WOLFSSL_VERIFY
cverifier botan BOTAN_PREFIX BOTAN_VERIFY

printf 'verifiers run: %s, with a disagreement or an error: %s\n' "$ran" "$bad"
[ "$ran" -gt 0 ] && [ "$bad" -eq 0 ]
